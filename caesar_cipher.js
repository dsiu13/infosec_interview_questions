// a = 97
// z = 112

// A = 65
// Z = 90


//Shift backwards first?
//Decrypt function

let caesarCipher = (message, shiftVal) => {

    let cipherArr = []

    for(i = message.length - 1; i >= 0; i--){

      if (message.charCodeAt(i) + shiftVal > 122){
         let decNum = message.charCodeAt(i) + shiftVal - 122 + 96
         let numChar = String.fromCharCode(decNum)
         cipherArr.push(numChar)
      } else {
         let decNum = message.charCodeAt(i) + shiftVal
         let numChar = String.fromCharCode(decNum)
         cipherArr.push(numChar)
      }
    }
    console.log(cipherArr.join(""))
};

caesarCipher("zed", 1)



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






let caesarCipher = (message) => {

    for(i = message.length - 1; i >= 0; i--){

      if (message.charCodeAt(i) + 1 > 122){
         console.log((message.charCodeAt(i) + 1 - 122) + 64)
      } else {
        console.log(message.charCodeAt(i) + 1)
     // console.log(String.fromCharCode(message.charCodeAt(i)))
      }

    }

};

caesarCipher("zed")
