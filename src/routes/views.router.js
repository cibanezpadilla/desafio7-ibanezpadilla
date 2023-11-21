import { Router } from "express";
import { manager } from "../dao/managersMongo/productManagerMongo.js";
import { cManager } from "../dao/managersMongo/cartManagerMongo.js";


const router = Router();

router.get("/login", (req, res) => {  
  if (req.session.passport){
    return res.redirect('/home')
  }  
  res.render("login", {style: "login"});  
});


router.get("/signup", (req, res) => {  
  if (req.session.passport){
    return res.redirect('/home')
  }   
  res.render("signup", {style: "signup"});
});




router.get("/home", async (req, res) => {  
  try {
      const products = await manager.findAll(req.query)
      const {payload, info, page, limit, order, query} = products
      const { nextPage, prevPage } = info
      const {category} = query      
      const productObject = payload.map(doc => doc.toObject()); 
      if (!req.session.passport){
        return res.redirect('/login')
      }
      const { first_name, email, isAdmin } = req.user;
      console.log(req.user)
      
      res.render('products', { user: { first_name, email, isAdmin }, productList: productObject, category, page, limit, order, nextPage, prevPage, style: "products" });          
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
});


router.get("/restaurar", (req, res) => {
  res.render("restore", {style: "restore"});
});


router.get("/error", (req, res) => {
  res.render("error", {style: "error"});
});







router.get('/home/:id', async (req, res) => {  
  try {
      const { id } = req.params
      const product = await manager.findById(id)              
      res.render('product', { product: product.toObject(), style: "productDetail" });           
    } catch (error) {
      res.status(500).json({ message: error.message });
    }
});



router.get('/cart/:cid', async (req, res) => {  
  try {
    const { cid } = req.params
    const response = await cManager.getCartProducts(cid)
    const array = response.products.map(doc => doc.toObject());    
    res.render('cart', {cartProductList: array,  style: "cart" })
}
catch (error){
    res.status(500).json({ message: error.message });
}
})



export default router;