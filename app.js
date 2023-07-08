
import { PublicKey, Signature, verify } from "ts-signify";
import jsQR from 'jsqr';

function stringToByteArray(input) {
  let result = [];

  for (let i = 0; i < input.length; i++) {
    result.push(input.charCodeAt(i));
  }

  return new Uint8Array(result);
}

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

