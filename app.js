

import jsQR from 'jsqr';

import { OpenSSL } from 'openssl.js';
import WasmFs from '@wasmer/wasmfs';

const wasmFs = new WasmFs();
wasmFs.fs.mkdirSync('/usr');
wasmFs.fs.mkdirSync('/usr/local');
wasmFs.fs.mkdirSync('/usr/local/ssl');
wasmFs.fs.writeFileSync('/usr/local/ssl/openssl.cnf', `
#
# OpenSSL configuration file.
#

# Establish working directory.

dir                 = .

[ ca ]
default_ca              = CA_default

[ CA_default ]
serial                  = $dir/serial
database                = $dir/certindex.txt
new_certs_dir               = $dir/certs
certificate             = $dir/cacert.pem
private_key             = $dir/private/cakey.pem
default_days                = 365
default_md              = md5
preserve                = no
email_in_dn             = no
nameopt                 = default_ca
certopt                 = default_ca
policy                  = policy_match

[ policy_match ]
countryName             = match
stateOrProvinceName         = match
organizationName            = match
organizationalUnitName          = optional
commonName              = supplied
emailAddress                = optional

[ req ]
default_bits                = 1024          # Size of keys
default_keyfile             = key.pem       # name of generated keys
default_md              = md5               # message digest algorithm
string_mask             = nombstr       # permitted characters
distinguished_name          = req_distinguished_name
req_extensions              = v3_req

[ req_distinguished_name ]
# Variable name             Prompt string
#-------------------------    ----------------------------------
0.organizationName          = Organization Name (company)
organizationalUnitName          = Organizational Unit Name (department, division)
emailAddress                = Email Address
emailAddress_max            = 40
localityName                = Locality Name (city, district)
stateOrProvinceName         = State or Province Name (full name)
countryName             = Country Name (2 letter code)
countryName_min             = 2
countryName_max             = 2
commonName              = Common Name (hostname, IP, or your name)
commonName_max              = 64

# Default values for the above, for consistency and less typing.
# Variable name             Value
#------------------------     ------------------------------
0.organizationName_default      = My Company
localityName_default            = My Town
stateOrProvinceName_default     = State or Providence
countryName_default         = US

[ v3_ca ]
basicConstraints            = CA:TRUE
subjectKeyIdentifier            = hash
authorityKeyIdentifier          = keyid:always,issuer:always

[ v3_req ]
basicConstraints            = CA:FALSE
subjectKeyIdentifier            = hash
`);

console.log("file written!");

(async function() {
  let openSSL = new OpenSSL({
      fs: wasmFs.fs,
      rootDir: "/",
      wasmBinaryPath: "./node_modules/openssl.js/dist/openssl.b64.wasm"
  });
  let result1 = await openSSL.runCommand(
    "genpkey -algorithm Ed25519 -out /private.pem"
  );
  let pK = wasmFs.fs.readFileSync("/private.pem", { encoding: "utf8" });
  console.log(pK);
  document.body.innerText = pK;
})();


/*
var video = document.createElement("video");
var canvasElement = document.getElementById("canvas");
var successElement = document.getElementById("success");
var successContentElement = document.getElementById("successcontent");
var canvas = canvasElement.getContext("2d");
var loadingMessage = document.getElementById("loadingMessage");
var outputContainer = document.getElementById("output");
var outputMessage = document.getElementById("outputMessage");
var outputData = document.getElementById("outputData");

function processCodeData(data) {
    console.log(data);
    // display success
    if (result) {
	successContentElement.innerHTML = "Machine ID: <b>" + signedMachineId + "</b><br>" + "Seconds Ago: <b>" + secondsAgo + "</b><br>Election ID: <tt>" + electionId.substring(0,10) + "</tt>";
	canvasElement.hidden = true;
	successElement.hidden = false;
	continueAnimation = false;
	outputContainer.hidden = true;
    } else {
	console.log("verification failed");
    }
}

var continueAnimation = true;
function tick() {
    loadingMessage.innerText = "⌛ Loading video..."
    if (video.readyState === video.HAVE_ENOUGH_DATA && continueAnimation) {
	loadingMessage.hidden = true;
	canvasElement.hidden = false;
	outputContainer.hidden = false;
	
	canvasElement.height = video.videoHeight;
	canvasElement.width = video.videoWidth;
	canvas.drawImage(video, 0, 0, canvasElement.width, canvasElement.height);
	var imageData = canvas.getImageData(0, 0, canvasElement.width, canvasElement.height);
	var code = jsQR(imageData.data, imageData.width, imageData.height, {
	    inversionAttempts: "dontInvert",
	});
	
	if (code) {
	    processCodeData(code.data);
	}
    }
    if (continueAnimation) {
	requestAnimationFrame(tick);
    }
}

document.getElementById('startvideo').onclick = () => {
    navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }).then(function(stream) {
	video.srcObject = stream;
	video.setAttribute("playsinline", true); // required to tell iOS safari we don't want fullscreen
	video.play();
	requestAnimationFrame(tick);
    });
}

*/
