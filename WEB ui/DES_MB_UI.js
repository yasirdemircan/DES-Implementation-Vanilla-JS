/*
Yasir Yakup Demircan
DES Encryption ECB mode implementation in Javascript

*/

//ASCII full message
var fullMSG = "Hello World"

//Ascii Message Block
var M = "";
//Binary Left/Right message
var ML = ""; //"01110100011001010111001101110100";
var MR = ""; //"01100001011000100110001101100100";


//Message left right after initial permutation
var ML2 = "";
var MR2 = "";

//64 bits initial key
var K64 = "0001001100110100010101110111100110011011101111001101111111110001";


//S-Boxes Class (Disabled for web import)
//var sBoxesClass = require("./Sboxes.js")
//var sBoxes = new sBoxesClass();

//Permuted choice 1 Array
var PC1L = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36];
var PC1R = [63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];

//Permuted choice 2 Array
var PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];

//Initial Permutation Array
var IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];

//Final permutation IP inverse
var IPinv = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];

//Expansion permutation Array
var EP = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];

//32 bit permutation after sBox
var P = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];



//Function to prepare blocks for encryption (padding/splitting)
function break2blocks() {
    // converting str to arr
    let strlen = fullMSG.length;
    let arr = fullMSG.split("");
    let finalStrings = [];
    // Adding padding for the multiblock
    for (let i = 0; i < (8 - (strlen % 8)); i++) {
        arr.push(" ");

    }



    // Splitting the string to 8 char len
    for (let j = 8; j <= arr.length; j = j + 8) {

        console.log(j);
        finalStrings.push(arr.slice(j - 8, j))
    }
    renderEL("Message with extra paddings: "+finalStrings);
    return finalStrings;

}



//56bits key
var K56L = "";
var K56R = "";

//Shift counts for key rounds
var roundShifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

//56 bits and 48 bits key arrays
var allKeys56 = [];
var allKeys48 = [];

//Convert text to binary string
function asc2bin(message) {
    ML = "";
    MR = "";

    for (let index = 0; index < 4; index++) {
        let len = message.charCodeAt(index).toString(2).length;

        //Paddings for 8bit completion
        if (len < 8) {
            if (len == 7) {
                ML += "0";
            }
            if (len == 6) {
                ML += "00";
            }
            if (len == 5) {
                ML += "000";
            }
        };

        ML += message.charCodeAt(index).toString(2);
    }
    for (let index = 4; index < message.length; index++) {
        let len = message.charCodeAt(index).toString(2).length;
        if (len < 8) {
            if (len == 7) {
                MR += "0";
            }
            if (len == 6) {
                MR += "00";
            }
            if (len == 5) {
                MR += "000";
            }
        };

        MR += message.charCodeAt(index).toString(2);
    }

    renderEL("64 bit Binary Message Block Left:"+ML);
    renderEL("64 bit Binary Message Block Right:"+MR);
    return ML + MR
}

//Initial permutation for left/right key parts
function initPermKey() {


    PC1L.forEach(function (perm) {
        K56L += K64[perm - 1]; //Convert char count to index
    });
    PC1R.forEach(function (perm2) {
        K56R += K64[perm2 - 1]; //Convert char count to index
    })


renderEL("56bit Key Left after PC1: "+K56L,"blue");
renderEL("56bit Key Right after PC1: "+K56R,"blue");
    // console.log("Init Key Left:",K56L,K56L.length);
    // console.log("Init Key Right:",K56R,K56R.length);
}


//Apply Initial Perm to message

function initPermMsg() {
    ML2 = "";
    MR2 = "";
    let fullMsg = ML + MR;

    IP.forEach(function (perm, index) {
        if (index < 32) {
            ML2 += fullMsg[perm - 1]
        } else {
            MR2 += fullMsg[perm - 1]
        }

    });

    renderEL("Message Left after Initial Permutation: "+ML2,"orange")
    renderEL("Message Right after Initial Permutation: "+MR2,"orange")

}

//Expansion permutation for the message
function expandPermMsg(msg) {
    let result = "";
    EP.forEach(function (perm) {
        result += msg[perm - 1]
    })
    renderEL("Message part after Expansion Permutation: "+result,"dodgerblue")
    return result
}


// Left shift for key generation  takes leftkey/rightkey and shift amount
function leftShift(C, D, amount) {
    let resC = "";
    let resD = "";
    if (amount == 1) {
        for (let i = 1; i < C.length; i++) {
            resC += C[i];
        }
        resC += C[0];

        for (let j = 1; j < D.length; j++) {
            resD += D[j];
        }
        resD += D[0];

    } else if (amount == 2) {
        for (let i = 2; i < C.length; i++) {
            resC += C[i];
        }
        resC += C[0];
        resC += C[1];

        for (let j = 2; j < D.length; j++) {
            resD += D[j];
        }
        resD += D[0];
        resD += D[1];

    }
    //console.log("Left Shift Left:",resC,resC.length);
    //console.log("Left Shift Right:",resD,resD.length);
    renderEL("Shifting key bits...","red")
    return {
        C: resC,
        D: resD
    };

}

// Spliting keys and shifting 

function keysBeforePerm() {
    //Initial key object into all keys
    var initKey = {
        C: K56L,
        D: K56R
    };
    allKeys56[0] = initKey;

    let counter = 0;
    roundShifts.forEach(function (round) {
        allKeys56[counter + 1] = leftShift(allKeys56[counter].C, allKeys56[counter].D, round)
        counter++;
    })


}

// Applying PC2 to keys
function finalizeKeys() {
    let returnKey = "";
    allKeys56.forEach(function (key, index) {

        PC2.forEach(function (perm) {
            let CD = key.C + key.D;
            returnKey += CD[perm - 1];
        })

        allKeys48[index] = returnKey;
        returnKey = "";

    });


}

//Simple exclusive or implementation 
function XOR(a, b) {
    let result = "";
    for (let i = 0; i < a.length; i++) {
        if (a[i] == b[i]) {
            result += "0"
        } else {
            result += "1"
        }
    }

    return result
}


// Applying P to message 
function Permutation32(msg) {
    let result = "";
    P.forEach(function (perm) {
        result += msg[perm - 1]
    });
    return result
}

//Applying inverse initial permutation to message

function finalPermutation(msg) {
    let result = "";
    IPinv.forEach(function (perm) {
        result += msg[perm - 1]
    })
    return result
};

// Converting binary to ascii
function bin2asc(bin) {
    let output = "";
    let decimals = [];
    for (let i = 0; i < bin.length; i = i + 8) {

        let toDec = "";
        toDec += bin[i] + bin[i + 1] + bin[i + 2] + bin[i + 3] + bin[i + 4] + bin[i + 5] + bin[i + 6] + bin[i + 7];
        decimals.push(parseInt(toDec, 2));
        toDec = "";
    }
    decimals.forEach(function (letter) {
        output += String.fromCharCode(letter)
    })

    return output;

}

//Processing single message block (XOR , Sbox , Permutation)
function processMsgPart(msg, key) {
    //Expand message part to 48 and XOR with key
    let msg48 = expandPermMsg(msg);
    let resXOR = XOR(msg48, key);
    let resXOR8 = [];
    let afterBox = [];
    let stringAfterBox = "";
    //Cutting into 8 pieces for Sboxes
    for (let i = 0; i < resXOR.length; i = i + 6) {
        resXOR8.push(resXOR.slice(i, i + 6));
    }



    //Apply sBoxes
    resXOR8.forEach(function (sixbit, index) {
        let MSBLSB = parseInt(sixbit[0] + sixbit[5], 2);
        let midbits = parseInt(sixbit[1] + sixbit[2] + sixbit[3] + sixbit[4], 2);
        afterBox.push(sBoxes[index + 1][MSBLSB][midbits]);
        //console.log("MSBLSB:",parseInt(MSBLSB,2),"Midbits:",parseInt(midbits,2),sixbit);
    });

    afterBox.forEach(function (bits) {
        let toBinary = bits.toString(2);

        //Adding less significant zeros lost in translation
        if (toBinary.length < 4) {
            if (toBinary.length == 1) {
                toBinary = "000" + toBinary;
            } else if (toBinary.length == 2) {
                toBinary = "00" + toBinary;
            } else if (toBinary.length == 3) {
                toBinary = "0" + toBinary;
            }
        }

        stringAfterBox += toBinary;
        //console.log(toBinary);
    });

    renderEL("Message part after Sbox: "+stringAfterBox,"Green");

    result = Permutation32(stringAfterBox);
    //console.log(result,result.length);
   renderEL("Message part after permutation: "+result,"yellowgreen")
    return result

}

//Encryption main function (Single block of encryption)
function Encrypt() {
    let afterENC = "";
    let result = "";


    initPermMsg();

    //Feistel structure work here!
    let L = ML2;
    let R = MR2;
    let Rcopy;
    allKeys48.forEach(function (key, index) {
        Rcopy = R;
        // Not using key0
        if (index != 0) {
            Rcopy = R;
            R = XOR(L, processMsgPart(R, key))
            L = Rcopy;


        }

    });

    //Reversing the 32bit blocks for final permutation IP inverse
    afterENC = R + L;
    result = finalPermutation(afterENC);

    console.log("Encrypted:", result, result.length);
    return result;
};

//Main decryption function (for single block of 64 bits)

function Decrypt(msg) {
    let afterDEC = "";
    let result = "";

    ML = msg.slice(0, 32); //10000101111010000001001101010100
    MR = msg.slice(32, 64); //00001111000010101011010000000101



    initPermMsg();

    let L = ML2;
    let R = MR2;
    let Rcopy;
    for (let i = 16; i > 0; i--) {

        Rcopy = R;
        R = XOR(L, processMsgPart(R, allKeys48[i]))
        L = Rcopy;


    }


    //Reversing the 32bit blocks for final permutation IP-1
    afterDEC = R + L;
    result = finalPermutation(afterDEC);
    return result;
    //console.log("Decrypted:",result,result.length);
}



//Running the example



function encryptAllBlocks() {



    renderEL("Encryption starts with Message :"+fullMSG+" and Key: "+K64,"crimson")
    let fullEncrypted = ""


    break2blocks().forEach(function (block) {
        let array2str = block.join("");
        M = array2str
        asc2bin(M);
        fullEncrypted += Encrypt();

    });

    console.log("Encrypted:", fullEncrypted, fullEncrypted.length);
    renderEL("EncryptedBIN: "+fullEncrypted);
    renderEL("EncryptedASCII: "+bin2asc(fullEncrypted));

 resetGlobalKeys();
    return fullEncrypted;

}

function resetGlobalKeys() {
               //56bits key
K56L = "";
K56R = "";
//56 bits and 48 bits key arrays
allKeys56 = []; 
allKeys48 = [];
}

function decryptAllBlocks(allBlocks) {
    renderEL("Decryption starts with Message :"+allBlocks+" and Key: "+K64,"crimson")

    let blockCount = allBlocks.length / 64;
    let blocks = [];
    let decryptedBlocks = [];
    for (let i = 64; i <= blockCount * 64; i = i + 64) {

        blocks.push(allBlocks.slice(i - 64, i));

    }

    blocks.forEach(function (encBlock) {
        decryptedBlocks.push(bin2asc(Decrypt(encBlock)));
    })


    renderEL("DecryptedASCII: "+decryptedBlocks.join(""))
    renderEL("DecryptedBIN:"+asc2bin(decryptedBlocks.join("")));
    resetGlobalKeys();

}

function renderEL(param,color) {
    let p = document.createElement("p");
    if (color) {
        p.style.color = color
    }
    p.innerHTML = param;
    document.getElementById("datadiv").appendChild(p);

}

function startENC_UI(text){
    fullMSG = text;
    initPermKey();
    keysBeforePerm();
    finalizeKeys();
   encryptAllBlocks();
}

function startDEC_UI(text){
    initPermKey();
    keysBeforePerm();
    finalizeKeys();
     decryptAllBlocks(text);
}
