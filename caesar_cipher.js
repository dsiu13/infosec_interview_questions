// a = 97
// z = 112

// A = 65
// Z = 90

//Shift backwards first?
//Decrypt function

let caesarCipher = (message, shift_val) => {

    lettersArr = message.split("")

    for(i = lettersArr.length - 1; i >= 0; i--){
      console.log(message.charCodeAt(i) + shift_val)
      // console.log(String.fromCharCode(message.charCodeAt(i)))
    }

};

caesarCipher("test string", 0)


if (message.charCodeAt(i) + shift_val > 122){
   (122 - (message.charCodeAt(i) + shift_val)) + 97

} else if(message.charCodeAt(i) + shift_val < 97){

}
