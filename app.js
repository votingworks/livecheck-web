

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
		var timestamp = new Date(result.timestamp);

		const metadata = [];
		if (result.system_hash && result.software_version) {
		    const system_hash_pretty = result.system_hash.substring(0, result.system_hash.length / 2) + "<br>" + result.system_hash.substring(result.system_hash.length / 2);
		    metadata.push(
			["System hash", "<tt>" + system_hash_pretty + "</tt>"],
			["Version", result.software_version]
		    )
		}
		metadata.push(
			["Machine ID", result.machine_id],
			["Election ID", "<tt>" + (result.election_id || "None") + "</tt>"],
			["Timestamp", timestamp.toLocaleDateString() + " " + timestamp.toLocaleTimeString()],
		);
		const innerHtml = metadata
			.map((item) => item[0] + ":<br><b>" + item[1] + "</b>")
			.join("<br><br>");

		successContentElement.innerHTML = innerHtml;
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

	if (code && code.data) {
	    console.log("got QR code -- " + code.data);
	}
	
	if (code && code.data &&
	    (code.data.startsWith("1//lc") ||
	     code.data.startsWith("1//shv1")
	    )
	   ) {
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
