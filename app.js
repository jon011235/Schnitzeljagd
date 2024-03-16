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

async function searchLocation(guess) {
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
    if (urlParams.has('start')){ //only makes sense if a camp is selected
        searchLocation(urlParams.get('start'));
    }
}

function pfalz(){
    data = {"locations": 
        [
            { answer: "cced28c6dc3f99c2396a5eaad732bf6b28142335892b1cd0e6af6cdb53f5ccfa", secret: "5jJ/foPy/nCUf6doclacRfuZu7MJE/cMNA5gC4QiBofTwBG1YVqkaUgoJ40ftp3D92ySBFpg5m8GComjYKQhInwcHnkvGm2Sn+Js62ZdcuivkkBFrV3WbS7h0Vce" },

            {
            "answer": "2baf1f40105d9501fe319a8ec463fdf4325a2a5df445adf3f572f626253678c9",
            "secret": "E1IFvUwpBQD9ZT9K3saDCr7KjtTk9Re86lLpwfgt50Sj32myHZYvuAkqC5ZMukdlssyFphKpKzqnM+SHbpcVqE2zXcCwUq5u22px7okGPoaoCfjwFk+mllrBovmp4Q=="
            },
            
            {
                "answer": "630a78299ecbe3d5151617784444b96bafb543605270c7483250e4273523291d",
                "secret": "V9D7zvjouAZOnZBqkyXionxOwhtyQew5jZwKswfAX2yBFvYe2Qq1pAG9I1jiyT6Qb9+kC6Ql3BoegxbXQlhm4LmQkq5PuTzvcPuYVNgizqnYKlgUImcBHv2bv6rn5w=="
            },
            {
                "answer": "5e2bf57d3f40c4b6df69daf1936cb766f832374b4fc0259a7cbff06e2f70f269",
                "secret": "r0ezd/ltPhog6S4/qmr0boII+L7AZ/eB56XUy04r9rKA17tKGLUwhWbrFSznTJKIzhMvJn4DZAV4KrkuaKcrWCuz1PHNSsGXjUxStLPqbgENCRKHuTPfuHIoH0ua6zelQRPABFhYkB8p"
              },
            {
                "answer": "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049",
                "secret": "QdpXH9IsN7TEdXSGquhzKulX3Kf83vKu2Qfth7T2viY8lW+4sMCWdNc+DAYjihlZMHeUOT3Wxsufc0YL2hRqP52c3QrQot4+StMWhoYYlF8ZpbQTQQhwZ//GnO+ayR2O5tH0D0tad1IV"
            },

            {
                "answer": "c61a3d0952f6c1981f49da21e5c66a0481d2c148a59ba4944489a9022fba6410",
                "secret": "CGixjmHWEUxvt9GrsrJkBf8mOqWVEZAU4IOnLWajR/uODz5edjVn5KOIef8RhMLnxLgNvT2e+CvjkGjZ0hx7w1wMJwxOVeRJfqkbMJlFK3OPP1qk9rF4dFP6cqSk"
            },

            {
                "answer": "a394e0a84c5b6fffd013b05e4a0235f6b04cee34a294bbd0283dae82a1fa74fe",
                "secret": "w8fWd4VrBvJYbM9blQwBFiGwftOPzjpnJLeo0XlNXtxioc8aexLCiDkE6GLzg4A5IcuTFJiAwtW9g9HdDoblYtUIbTh6S2OQ7ripN+9ShjvHFPQqP4fBR9StYRds"
              },

            {
                "answer": "611f3c5e6dd8232acc25d9107f475fdae241fe1af9eb81fde7c8e8c9a812dc09",
                "secret": "MbA5bEU/+ObkXzI28tsycIfwTXXJpXG0rCwYPIl2CI0hpM/ZAfwzAVQxr/0XeJF1LtnkVXK4+Zby/GNeew4CL47d+/DsF8COOvXryeXU29Me0EySRU+gzz4A9gA="
              },

            {
            "answer": "2e89685cf91ac02b317c0e6aa69ba934f9c372a75c7acd9141e48233c4a9cae4",
            "secret": "jy67mb3fgdVUIyWzPXXUia+aI2o0bFVZgOaRku7I7llsUf3xOJoJku3vyOlrOX7lQNpabaT2Lmn93XZJVeRlOuDKmnDHqwCiDNUnaOKrep8t3wzMh2LM2CDxaklU"
            }

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
                "answer": "2baf1f40105d9501fe319a8ec463fdf4325a2a5df445adf3f572f626253678c9",
                "secret": "Lcf5fRcnQ84zhvtbHDXsIbU6G795hppgO4PJ06uij2UrQE92uPannQ1tlJHzfFzdGGXI41meAXfxssuuVJFE9KOnwpODWc5C3/z5vHrvtqxR0Lpp"
            },
            {
                "answer": "5e2bf57d3f40c4b6df69daf1936cb766f832374b4fc0259a7cbff06e2f70f269",
                "secret": "eE0Hy8p+wb4CmxAK8qE71lDw+oQomZbKcyJzEmorYaEjFyK1H64NQVf5AFm96oPAMR9bbeLEJ4orBhhafL1EpybW2UtrGNcMR+y3I1DjycFBH7FT"
            },
            {
                "answer": "73475cb40a568e8da8a045ced110137e159f890ac4da883b6b17dc651b3a8049",
                "secret": "6UNQlPbYCK/dW0YEQAH6tUuaiSm2b0s1ca3r3QmKN9ZgkJoVvcP0JUgtupW4RC7XDAcs9K1/SXlQ1IeYwoeE1IknGsxCWFyDoPVy/RBQKHmGxkX5"
            },
            {
                "answer": "a394e0a84c5b6fffd013b05e4a0235f6b04cee34a294bbd0283dae82a1fa74fe",
                "secret": "0ToISUuHBW55YkLVV/QlflV7ak3HkvzuDmxIKEI4riGnOav2O90wCebZCCSq5rjJZGZWUmi8XdT+98kog43ARNbB5tUwa3BI0gJHyQOfW5/i7Fu9"
            },
            {
                "answer": "2e89685cf91ac02b317c0e6aa69ba934f9c372a75c7acd9141e48233c4a9cae4",
                "secret": "VeBemlHmi6SxRzj95r50w0SWWXRjD6Q/shMM66uzshWsMb7J2FtnsS/9r7Ik4NDOlL0iHpq1yiiCi7yXsfxQVSdaPsi2t+0Zon43P0YBDPOgG+Wy"
            },
            {
                "answer": "b5159f2e7e14312abaac8fe9f8475604ecd1baf9ad81475c523c66ed38805a52",
                "secret": "AFVb8I2Fk9F+VGjhgqdtev1TzMwZAS8fVzkeUqIorjip04H8SwdlYSVnkO+jy0OExAReg7GN4kKEb5r8fV5vEYoMH0jUPECOtoWEfusBgyTGD0ek"
            },
            {
                "answer": "630a78299ecbe3d5151617784444b96bafb543605270c7483250e4273523291d",
                "secret": "D3Xpwl3aBkmuHmDugELE0HUSS1MwKOszxFPUVvvLq2RL2c/t2jcADpSkOAgLz5e2d2QKTHvw/x4SwzJ23IZWzCfx4jiurU2u8phKUIC9+KQCWdLN"
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
