import express from 'express';
import bodyParser from 'body-parser';
import { hash , compare } from 'bcrypt';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { signup, signin, signupAuth, signinAuth } from './db/db.mjs';

// WebAuth ---------------------------------------------------------
import { generateRegistrationOptions, verifyRegistrationResponse, generateAuthenticationOptions, verifyAuthenticationResponse } from '@simplewebauthn/server';
import { isoUint8Array } from '@simplewebauthn/server/helpers';
import base64url from 'base64url';

const authenticators = {};
const rpID = 'localhost'; // Relying Party Identifier
const PORT = process.env.PORT || 3000;
const expectedOrigin = 'http://localhost:' + PORT;
// ------------------------------------------------------------------

// Oauth ------------------------------------------------------------
import querystring from 'querystring';
import cookieParser from 'cookie-parser';
import secret from './client_secret.json' assert {type: "json"}; 
import { error } from 'console';

const CLIENT_ID = secret.web.client_id;
const CLIENT_SECRET = secret.web.client_secret;
const REDIRECT_URI = 'http://localhost:3000/auth/google/callback';
// -------------------------------------------------------------------

const app = express();
app.use(cookieParser());
app.use(express.static('public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

const { urlencoded } = bodyParser;

const __dirname = dirname(fileURLToPath(import.meta.url));

app.use(urlencoded({ extended: true }));
app.use(express.static(join(__dirname, 'public')));

// Registration endpoint
app.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    signup(username, password);

    res.send('User registered successfully');
  } catch (error) {
    res.status(500).send('Error registering new user');
  }
});

// Login endpoint
app.post('/login', async (req, res) => {
  
    const { username, password } = req.body;
    try{
    let user = await signin(username, password);
    if (!user) {
      return res.status(400).send('Invalid credentials');
    }
      res.send('Login successful');
    } catch (error) {
      res.status(500).send('Error logging in');
    }

});

app.listen(PORT, (err) => {
  if (err) console.log(err);
  
  console.log('Server is running on http://localhost:' + PORT);
});


// OAuth: handle the auth request
app.get('/auth/google', (req, res) => {
    const authorizationUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    const params = {
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT_URI,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'online'
    };
    res.redirect(`${authorizationUrl}?${querystring.stringify(params)}`);
});

// Oauth: Handle the response from Google's OAuth server
app.get('/auth/google/callback', async (req, res) => {
    const code = req.query.code;
    if (!code) {
        return res.status(400).send('Authorization code is missing');
    }
    try {
        const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: querystring.stringify({
                code,
                client_id: CLIENT_ID,
                client_secret: CLIENT_SECRET,
                redirect_uri: REDIRECT_URI,
                grant_type: 'authorization_code'
            })
        });

        if (!tokenResponse.ok) {
            throw new Error(JSON.stringify(await tokenResponse.json()));
        }

        const tokenData = await tokenResponse.json();
        const accessToken = tokenData.access_token;

        if (!accessToken) {
            throw new Error('Access token is missing in the response');
        }

        res.cookie('token', accessToken, { httpOnly: true });
        res.redirect('/dashboard');
    } catch (error) {
        console.error(error);
        res.status(500).send('Internal Server Error');
    }
});

// OAuth: Show a user dashboard that displays user information obtained through Google's API using the access token
app.get('/dashboard', async (req, res) => {
    if (!req.cookies.token) {
        return res.status(401).send('Unauthorized');
    }
    const accessToken = req.cookies.token;

    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v1/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` }
    });

    if (!userInfoResponse.ok) {
        throw new Error('Failed to fetch user info');
    }

    const userData = await userInfoResponse.json();

    res.send(`
        <h1>Login successful</h1>
        <p>Welcome ${userData.email}</p>
    `);
});


// WebAuth: Registration Endpoint
app.post('/register/start', async (req, res) => {
  // Extract username from request body
  const { username } = req.body;
  if (!username) {
    return res.status(400).send({ error: 'Username is required' });
  }

  // Check if user already exists
  const user = await signinAuth(username);
  if (user) {
    return res.status(400).send({ error: 'User already exists' });
  }

  // Generate registration options
  const registrationOptions = await generateRegistrationOptions({
    rpName: 'Future Of Authentication',
    rpID,
    userID: isoUint8Array.fromUTF8String(base64url(Buffer.from(username))),
    userName: username,
    timeout: 60000, // Timeout for the request in milliseconds
    attestationType: 'none',
    authenticatorSelection: {
      residentKey: 'discouraged',
    },
    supportedAlgorithmIDs: [-7, -257],
  });

  // Store the challenge temporarily for verification in the next step
  authenticators[username] = {
    challenge: registrationOptions.challenge,
  };

  // Send registration options to the client
  return res.send(registrationOptions);
});

// Endpoint to finish the registration process
app.post('/register/finish', async (req, res) => {
  const { username, attestationResponse } = req.body;

  // Retrieve the stored challenge from the 'authenticators' object
  const expectedChallenge = authenticators[username].challenge;

  let verification;
  try {
    // Verify the registration response
    verification = await verifyRegistrationResponse({
      response: attestationResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      requireUserVerification: true,
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Check if verification was successful
  const { verified } = verification;
  if (verified) {
    // Prepare user data for storage
    const user = {
      devices:[{
        credentialPublicKey: base64url.encode(verification.registrationInfo.credentialPublicKey),
        credentialID: base64url.encode(verification.registrationInfo.credentialID),
        transports: attestationResponse.response.transports,
      }],
      userID: base64url(Buffer.from(username)),
      userName: username,
    };

    // Remove the temporary authenticator
    authenticators[username] = undefined;

    try {
      // Store the user in the database
      await signupAuth(username, user);
    }
    catch (error) {
      return res.status(400).send({ error: error.message });
    }

    // Send verification result to the client
    return res.send({ verified });
  } else {
    return res.status(400).send({ error: 'Unable to verify registration' });
  }
});

// WebAuth: Login Endpoint
app.post('/login/start', async (req, res) => {
  const { username } = req.body;
  // Verify if the user exists
  const user = await signinAuth(username);
  if (!user) {
    return res.status(400).send({ error: 'User does not exist' });
  }

  // Generate authentication options
  const options = {
    rpID,
    timeout: 60000, // Timeout for the request in milliseconds
    userVerification: 'required',
    allowCredentials: user.devices.map((device) => ({
      id: new Uint8Array(base64url.toBuffer(device.credentialID)),
      type: 'public-key',
      transports: device.transports,
    })),
  };

  const authenticationOptions = await generateAuthenticationOptions(options.toString());

  // Store the challenge for later use during verification
  authenticators[username] = {
    currentChallenge: authenticationOptions.challenge,
  };

  // Send authentication options to the client
  return res.send(authenticationOptions);
});

// Endpoint to finish the login process
app.post('/login/finish', async (req, res) => {
  const { username, assertionResponse } = req.body;
  const expectedChallenge = authenticators[username].currentChallenge;

  const user = await signinAuth(username);
  const device = user.devices[0];

  let verification;
  try {
    // Verify the authentication response
    verification = await verifyAuthenticationResponse({
      response: assertionResponse,
      expectedChallenge,
      expectedOrigin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: new Uint8Array(base64url.toBuffer(device.credentialID)),
        credentialPublicKey: new Uint8Array(base64url.toBuffer(device.credentialPublicKey)),
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(400).send({ error: error.message });
  }

  // Send the verification result to the client
  const { verified } = verification;

  if (verified)
    return res.send(true);
  else 
    return res.status(400).send(false);
});


app.get('/authDashboard', async (req, res) => {
  const urlParams = new URLSearchParams(req.originalUrl);

  console.log(urlParams.get('username'));
  console.log(urlParams.get('registered'));
  
  if(urlParams.get('registered') === 'true')
    return res.send(`
      <p>User registered successfully</p>
    `)
  else if (urlParams.get('registered') === 'false')
    return res.send(`
      <p>Error: User registration failed</p>
    `)

  urlParams.get('username') ? res.send(`
  <h1>Login successful</h1>
  <p>Welcome ${urlParams.get('username')}!</p>
  `): res.status(400).send(`
  <h1>Login failed</h1>
  `)
});