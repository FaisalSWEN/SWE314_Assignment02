import express from 'express';
import bodyParser from 'body-parser';
import { hash , compare } from 'bcrypt';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { signup, signin } from './db/db.mjs';

// Oauth ------------------------------------------------------------
import querystring from 'querystring';
import cookieParser from 'cookie-parser';
import secret from './client_secret.json' assert {type: "json"}; 

const app = express();
app.use(cookieParser());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const CLIENT_ID = secret.web.client_id;
const CLIENT_SECRET = secret.web.client_secret;
const REDIRECT_URI = 'http://localhost:3000/auth/google/callback';
// -------------------------------------------------------------------

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

app.listen(PORT, () => {
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