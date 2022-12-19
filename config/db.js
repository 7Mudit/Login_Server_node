const mongoose=require("mongoose");
//for reading env files
require('dotenv').config();
mongoose.connect(process.env.MONGODB_URI,{useNewUrlParser:true,useUnifiedTopology:true})
.then(()=>{
    console.log("DB Connected");
})
.catch((err)=>console.log(err));

