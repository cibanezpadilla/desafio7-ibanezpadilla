import mongoose from "mongoose";

/* const URI =
  "mongodb+srv://coderhouse:coderhouse@cluster0.sugvijj.mongodb.net/DB47315PI?retryWrites=true&w=majority"; */
const URI = 
    "mongodb+srv://cibanez:JUiXF4gBSbSulLkt@cluster0.21urnbo.mongodb.net/ecommerce?retryWrites=true&w=majority";

mongoose
  .connect(URI)
  .then(() => console.log("Conectado a la DB"))
  .catch((error) => console.log(error));