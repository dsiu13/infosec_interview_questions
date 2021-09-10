// a = 97
// z = 112

// A = 65
// Z = 90

//To Do
// Fix for multiple word strings...
// Add ability to use a negative shift val
// handle punctuation and language special chars
// allow user to pass an array of numbers and convert to letters?


let caesarCipher = (message, shiftVal) => {

    let cipherArr = []

    for(i = 0; i <= message.length - 1; i++) {

         letterDec = message.charCodeAt(i) + shiftVal

      if (letterDec > 122) {

         let decNum = letterDec - 122 + 96
         let numChar = String.fromCharCode(decNum)
         cipherArr.push(numChar)

      } else if(letterDec <= 122 && letterDec > 96) {

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


caesarCipher("e", 1)

////////////////////////////////////////////////////////////////////////////////

let caesarPlain = (message, shiftVal) => {

    let plainrArr = []


    for(i = 0; i <= message.length - 1; i++) {

         letterDec = message.charCodeAt(i) - shiftVal

      if (letterDec > 122) {

         let decNum = letterDec - 122 + 96
         let numChar = String.fromCharCode(decNum)
         plainrArr.push(numChar)

      } else if(letterDec < 122 && letterDec > 100) {

         let numChar = String.fromCharCode(letterDec)
         plainrArr.push(numChar)

      } else if(letterDec > 90) {

         let decNum = letterDec - 90 + 64
         let numChar = String.fromCharCode(decNum)
         plainrArr.push(numChar)

      } else {

         let numChar = String.fromCharCode(letterDec)
         plainrArr.push(numChar)
      }

    }
       console.log(plainrArr.join(""))
    // return plainrArr.join("")
};
