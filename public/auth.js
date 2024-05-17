import {
  startRegistration,
  startAuthentication,
} from 'https://cdn.skypack.dev/@simplewebauthn/browser';

export async function register() 
{
  const username = document.getElementById('usernameAuth').value;

  // Begin registration process to get options
  let optionsRes = await fetch('/register/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username }),
  });

  let options = await optionsRes.json();
  if (options.error) {
    return alert(options.error);
  }

  // Use @simplewebauthn/browser to start registration
  let attestation = await startRegistration(options);

  // Send attestation response to server
  let verificationRes = await fetch('/register/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      attestationResponse: attestation,
    }),
  });
  let verificationResult = await verificationRes.json();

  alert(`Registration ${verificationResult ? 'successful' : 'failed'}`);
}
document.getElementById('registerBtn').addEventListener('click', register);



export async function login() 
{
  const username = document.getElementById('usernameAuth').value;

  // Begin authentication process to get options
  let optionsRes = await fetch('/login/start', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ username }),
  });
  let options = await optionsRes.json();

  if (options.error) {
    return alert(options.error);
  }

  // Use @simplewebauthn/browser to start authentication
  console.log(options);

  let assertion = await startAuthentication(options);

  // Send assertion response to server
  let verificationRes = await fetch('/login/finish', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      username,
      assertionResponse: assertion,
    }),
  });
  let verificationResult = await verificationRes.json();

  alert(`Login ${verificationResult ? 'successful' : 'failed'}`);
}

document.getElementById('loginBtn').addEventListener('click', login);