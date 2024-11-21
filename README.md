# LiveCheck

A web application that checks a VotingWorks LiveCheck-QR code, its
signature against known machine public keys.

## Development notes

- This application uses a Python Flask backend and Vite to build a JS frontend, built and served from `dist/`
- Server code lives in `server/` and client code roots in `app.js`
- To test the server, add a **main** entrypoint to `app.py` and run `python3 -m server.app` or `python3 app.py`
- To test the end to end flow locally/with a phone camera:
  - Add a **main** entrypoint to `app.py` with `app.run(port=5000)`
  - Add a `vite.config.js` to the root directory that sets a proxy for the server calls to `localhost:5000`
  - Run the client with `npm run dev` and the server with `python3 -m server.app`
  - In a separate terminal, expose the client to the internet with `ngrok http 3000`
  - On your phone, access the client using the url provided by ngrok
- Developing on Linux is recommended to match production
