
import { PublicKey, Signature, verify } from "ts-signify";
import jsQR from 'jsqr';

function stringToByteArray(input) {
  let result = [];

  for (let i = 0; i < input.length; i++) {
    result.push(input.charCodeAt(i));
  }

  return new Uint8Array(result);
}


/*
const message = stringToByteArray("Hello!\n");
const signature = Signature.import("untrusted comment: \nRWQjxsWYC1ei4uz+kFem6eK50EvLxr0rWGN0AkZwsS/EDmgyh9tig7bXJDvHE2PBO5G3Z8KvRi0g4q7yXYWo++4TegKvaG+GMAI=");
const pubkey = PublicKey.import("untrusted comment: \nRWQjxsWYC1ei4jZusPuwEvJvxgLiR3ex6h60/Q4BbX4cVTWFrDonl58b");

console.log("verify: ", verify(message, signature, pubkey));
*/


import publicKeys from './pubkeys.json';
console.log(publicKeys);

var video = document.createElement("video");
var canvasElement = document.getElementById("canvas");
var successElement = document.getElementById("success");
var successContentElement = document.getElementById("successcontent");
var canvas = canvasElement.getContext("2d");
var loadingMessage = document.getElementById("loadingMessage");
var outputContainer = document.getElementById("output");
var outputMessage = document.getElementById("outputMessage");
var outputData = document.getElementById("outputData");

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
	    }

	    if (code_url) {
		const {protocol, hostname, pathname, port, searchParams} = code_url;
		if (protocol != 'https:' || hostname != 'check.voting.works' || pathname != '/' || port != '') {
		    return;
		}

		const machineId = searchParams.get("m");
		const payload = searchParams.get("p");
		const signature = searchParams.get("s");
		
		console.log("got", machineId, payload, signature);
		
		if (!machineId || !payload || !signature) {
		    return;
		}
		
		// verify signature
		const message = stringToByteArray("lc." + payload);
		const fullSignature = Signature.import("untrusted comment: \n" + signature);
		const pubkey = PublicKey.import("untrusted comment: \n" + publicKeys[machineId]);

		const result = verify(message, fullSignature, pubkey);
		const [signedMachineId, timestamp, electionId] = payload.split('|');
		const secondsAgo = (new Date().getTime() - parseInt(timestamp)) / 1000;
		// display success
		if (result) {
		    successContentElement.innerHTML = "Machine ID: <b>" + signedMachineId + "</b><br>" + "Seconds Ago: <b>" + secondsAgo + "</b><br>Election ID: <tt>" + electionId + "</tt>";
		    canvasElement.hidden = true;
		    successElement.hidden = false;
		    continueAnimation = false;
		    outputContainer.hidden = true;
		} else {
		    console.log("verification failed");
		}
	    }
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

