import { json } from "express";

process.on("message", (msg) => {
  function generator(rad) {


    
    const arr = [];
    const obj = {};
   
    for (let index = 1; index < rad;  index++) {
      let numb = Math.floor(Math.random() * 1000 + 1);
      arr.push(numb)

    }
    
    
    const arrOrdenado = arr.sort()
    let cont = 1
     for (let i=1; i<arrOrdenado.length;i++){
        if(arrOrdenado[i+1] === arrOrdenado [i]){
            cont++
        }else{
            obj[arrOrdenado[i]]=cont;
           
            cont = 1
        }
    }
    
    
   
    return obj;
  }

  const random = generator(msg)

  process.send((random))
  process.end
});

process.send('listo')