
import { PublicKey, Signature, verify } from "ts-signify";
import jsQR from 'jsqr';

function stringToByteArray(input) {
  let result = [];

  for (let i = 0; i < input.length; i++) {
    result.push(input.charCodeAt(i));
  }

  return new Uint8Array(result);
}

const message = stringToByteArray("Hello!\n");
const signature = Signature.import("untrusted comment: verify with test.pub\nRWQjxsWYC1ei4uz+kFem6eK50EvLxr0rWGN0AkZwsS/EDmgyh9tig7bXJDvHE2PBO5G3Z8KvRi0g4q7yXYWo++4TegKvaG+GMAI=");
const pubkey = PublicKey.import("untrusted comment: signify public key\nRWQjxsWYC1ei4jZusPuwEvJvxgLiR3ex6h60/Q4BbX4cVTWFrDonl58b");

console.log("verify: ", verify(message, signature, pubkey));

var video = document.createElement("video");
var canvasElement = document.getElementById("canvas");
var successElement = document.getElementById("success");
var canvas = canvasElement.getContext("2d");
var loadingMessage = document.getElementById("loadingMessage");
var outputContainer = document.getElementById("output");
var outputMessage = document.getElementById("outputMessage");
var outputData = document.getElementById("outputData");

/*navigator.mediaDevices.getUserMedia({ video: { facingMode: "environment" } }).then(function(stream) {
  video.srcObject = stream;
  video.setAttribute("playsinline", true); // required to tell iOS safari we don't want fullscreen
  video.play();
  requestAnimationFrame(tick);
});

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
      var code_url
      try {
	// extract payload and signature
	code_url = new URL(code.data);
      } catch(err) {
	return;
      }
      
      const {protocol, hostname, pathname, port, searchParams} = code_url;
      
      if (protocol != 'https' || hostname != 'check.voting.works' || pathname != '/' || port != '') {
	return;
      }
      
      const {p: payload, s: signature} = searchParams;
      
      if (!p || !s) {
	return;
      }
      
      // verify signature
      
      // display success
      if () {
        canvasElement.hidden = true;
	successElement.hidden = false;
	continueAnimation = false;
        outputContainer.hidden = true;
      }
    }
  }
  if (continueAnimation) {
    requestAnimationFrame(tick);
  }
}
*/
