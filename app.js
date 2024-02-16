//Setup globals
data = {}

var map = L.map('map').setView([49.442778, 7.896667], 13);

L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,}).addTo(map);

//process URL parameters
const queryString = window.location.search;
const urlParams = new URLSearchParams(queryString);
if (urlParams.has('camp')){
    switch (urlParams.get('camp')) {
        case "pfalz":
            pfalz();
            break;
        case "stingbert":
            stingbert();
            break;
        default:
            alert("unkown camp");
            break;
    }
}

async function searchLocation() {
    var guess = document.getElementById("searchInput").value.toLowerCase();
    for (const entry of data["locations"]) {
        if (entry.answer == (await sha256(guess))) {
            result = await decrypt(entry.secret, guess);
            json = JSON.parse(result);
            var marker = L.marker([json["lat"], json["lon"]]).addTo(map);
            marker.bindPopup(json["message"])//.openPopup(); //TODO should it open automatically?
            return;
        }
    }
    alert("Kein Treffer");

}

function hide_start_screen(){
    document.getElementById("start-container").style.display="none"
    document.getElementById("schnitzeljagd").removeAttribute("hidden");
}

//TODO given parameters on URL do this automatically
function setup_schnitzeljagd(){
    hide_start_screen();
    map.setView(data.position, 15);
    map.invalidateSize();
}

function pfalz(){
    data = {"locations": 
        [
            {
            answer: "bffa164be2502c9fa31e1a50ffb75c7b3b9982bd6c27a5f43208a2559d7ed588",//rot
            secret: "UmHVK5XYQu1G33YqzjUDfogvtcbQ3W4Vnrhyj8Oybcs15dqDPsdM+7C99RliW9KVbOB1Xc8OeY3P7stQrVQTqXJDO6sktxFtUSUxCc0P1HnIgYKd9yo="
            },
            {
                "answer": "bffa164be2502c9fa31e1a50ffb75c7b3b9982bd6c27a5f43208a2559d7ed588",
                "secret": "IAvicABDsl5OUI2p16tnIxNY2uvq8syosPrerpk7656bcL7OAUKKQLp8ZJuB1ZMa0QPq5ZRrdjKSpEqiEISN25UdpktuJUEfGkohDONQZuMKfYe1Z98="
            },
            //Add more as needed
        ],
        "position": [49.442778, 7.896667]
    };
    setup_schnitzeljagd();
}

function stingbert(){
    data = {"locations": 
        [
            {
            answer: "echo",
            secret: "U2FsdGVkX1+MgkXaWVJK9M7u+PnrgUhJF5jqcB8jfyE="
            },
            {
            answer: "footsteps",
            secret: "U2FsdGVkX1+nkGo3jPY0HMb+Sl0t1CJ+w4V3R+eoWgU="
            },
            //Add more as needed
        ],
        "position": [49.278889, 7.115]
    };
    setup_schnitzeljagd();
}

function create_location(answer, lat, lon, message){
    json = '{"lat": "'+lat+'","lon": "'+lon+'","message": "'+message+'"}'
    sha256(answer).then(hash => 
        encrypt(json, answer).then(result=>console.log({
            answer: hash,
            secret: result
            },))
    );
}

async function sha256(message) {
    // Convert message to ArrayBuffer
    const encoder = new TextEncoder();
    const hash = encoder.encode(message);
  
    // Generate hash
    const hashBuffer = await crypto.subtle.digest('SHA-256', hash);
  
    // Convert ArrayBuffer to hex string
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  
    return hashHex;
}

// Function to decrypt the secret
async function decrypt(encryptedText, password) {
    password = password.toLowerCase();
    // Decode Base64
    const encryptedArray = Uint8Array.from(atob(encryptedText), c => c.charCodeAt(0));

    // Derive key from password
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );
    const key = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: new Uint8Array([84, 211, 107, 16, 247, 146, 89, 22, 33, 218, 155, 71, 91, 206, 90, 97]),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["decrypt"]
    );

    // Decrypt using AES-GCM
    const decryptedArray = await window.crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: encryptedArray.slice(0, 12) // IV length for AES-GCM is 12 bytes
        },
        key,
        encryptedArray.slice(12) // Remove IV from the encrypted array
    );

    return new TextDecoder().decode(decryptedArray);
}

async function encrypt(secret, password) {
    const encoder = new TextEncoder();
    secret = encoder.encode(secret).buffer;

    // Generate a random initialization vector (IV)
    const iv = window.crypto.getRandomValues(new Uint8Array(12)); // 12 bytes = 96 bits (recommended for AES-GCM)

    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    // Derive a random encryption key
    const key = await window.crypto.subtle.deriveKey(
        {
            "name": "PBKDF2",
            salt: new Uint8Array([84, 211, 107, 16, 247, 146, 89, 22, 33, 218, 155, 71, 91, 206, 90, 97]),
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["decrypt", "encrypt"]
    );

    // Encrypt the secret using AES-GCM
    const encryptedData = await window.crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        secret
    );

    // Combine IV and encrypted data
    const ivAndEncryptedData = new Uint8Array([...iv, ...new Uint8Array(encryptedData)]);

    // Encode the combined data as Base64
    const base64Encoded = btoa(String.fromCharCode.apply(null, ivAndEncryptedData));

    // Display the Base64-encoded encrypted secret
    return base64Encoded
}
