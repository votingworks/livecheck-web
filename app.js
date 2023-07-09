

import jsQR from 'jsqr';


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
    console.log("DATA==" + data + "==");
    fetch('/api/check', {
	method: 'POST',
	headers: {
            'Content-Type': 'text/plain'
	},
	body: data
    })
	.then(response => response.text())
	.then(text => {
	    if (text != "error") {
		const result = JSON.parse(text);
		successContentElement.innerHTML = "Machine ID: <b>" + result.machine_id + "</b><br>" + "Timestamp: <b>" + result.timestamp + "</b><br>Election ID: <tt>" + result.election_id + "</tt>";
		canvasElement.hidden = true;
		successElement.hidden = false;
		continueAnimation = false;
		outputContainer.hidden = true;
	    } else {
		console.log("verification failed");
	    }
	})
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
	
	if (code && code.data && code.data.startsWith("1//lc")) {
	    processCodeData(code.data);
	    continueAnimation = false;
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

