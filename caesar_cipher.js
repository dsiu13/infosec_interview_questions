// a = 97
// z = 112

// A = 65
// Z = 90


//Shift backwards first?
//Decrypt function

let caesarCipher = (message, shiftVal) => {

    let cipherArr = []


    for(i = 0; i <= message.length - 1; i++) {

         letterDec = message.charCodeAt(i) + shiftVal

      if (letterDec > 122) {

         let decNum = letterDec - 122 + 96
         let numChar = String.fromCharCode(decNum)
         cipherArr.push(numChar)

      } else if(letterDec < 122 && letterDec > 103) {

         let numChar = String.fromCharCode(letterDec)
         cipherArr.push(numChar)

      } else if(letterDec > 90) {

         let decNum = letterDec - 90 + 64
         let numChar = String.fromCharCode(decNum)
         cipherArr.push(numChar)

      } else {

         let numChar = String.fromCharCode(letterDec)
         cipherArr.push(numChar)
      }

    }
       console.log(cipherArr.join(""))
    // return cipherArr.join("")
};


caesarCipher("test", 1)




////////////////////////////////////////////////////////////////////////////////


//Shift backwards first?
//Decrypt function

let rotCipher = (message) => {

    for(i = message.length - 1; i >= 0; i--){
      console.log(message.charCodeAt(i) + 13)
      // console.log(String.fromCharCode(message.charCodeAt(i)))
    }

};

//set to start value
if (message.charCodeAt(i) + 13 > 122){
   (122 - (message.charCodeAt(i) + 13)) + 97

} else if(message.charCodeAt(i) + 13 < 97){

}


let caesarCipher = (message, shiftVal) => {

    let cipherArr = []

    for(i = message.length - 1; i >= 0; i--){
         letterDec = message.charCodeAt(i) + shiftVal
      if (letterDec > 122){
         let decNum = letterDec - 122 + 96
         let numChar = String.fromCharCode(decNum)
         cipherArr.push(numChar)
      } else {
         // let decNum = letterDec
         let numChar = String.fromCharCode(letterDec)
         cipherArr.push(numChar)
      }
    }
    console.log(cipherArr.join(""))
};


caesarCipher("zed", 1)
