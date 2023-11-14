import { Router } from "express";
import { manager } from "../dao/managersMongo/productManagerMongo.js";

const router = Router();


/* GET PRODUCTS */
router.get("/", async (req, res) => {
    try {
        const products = await manager.findAll(req.query);
        //if (!products.length){
        //    return res.status(404).json({message: 'Products not found'})    
        //} 
        res.status(200).json({ message: "Products found", products });
        //res.render("catalogue", {products});
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});




/* GET PRODUCTS BY ID */
router.get('/:id', async (req, res) => {
    try{
        const {id} = req.params
        const productById = await manager.findById(id)        
        res.status(200).json({ message: "Product found", productById });
    }
    catch(error){
        res.status(500).json({ message: error.message });
    }        
})




/* ADD PRODUCT */
router.post("/", async (req, res) => {
    try {
      const createdProduct = await manager.createOne(req.body);
      res
        .status(200)
        .json({ message: "Product created", product: createdProduct });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });



/* DELETE PRODUCT */
router.delete("/:idProduct", async (req, res) => {
    const { idProduct } = req.params;
    try {
        await manager.deleteOne(idProduct);
        res.status(200).json({ message: "Product deleted" });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});




/* UPDATE PRODUCT */
router.put("/:idProduct", async (req, res) => {
    const { idProduct } = req.params;
    try {
        await manager.updateOne(idProduct, req.body);
        res.status(200).json({ message: "Product updated"});
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
  });



export default router