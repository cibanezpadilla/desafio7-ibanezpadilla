import { cartsModel } from "../../db/models/carts.model.js";

/* import { prodmanager } from "./productManagerMongo.js"; */

class CartsManager {
    async createCart() {
        const result = await cartsModel.create({products: []});
        return result;
    }


    async getCartProducts(cid) {
        const result = await cartsModel
        .findById(cid)
        .populate("products.product")
        return result;                    
    }


    async addProductToCart(cid, pid){
        const selectedCart = await cartsModel.findById(cid);        
        const productIndex = selectedCart.products.findIndex(p => p.product.equals(pid));
        if (productIndex !== -1) {
            selectedCart.products[productIndex].quantity += 1;
        } else {
            selectedCart.products.push({ 
                product: pid, 
                quantity: 1 
            });
        }
        /* await cartsModel.updateOne({ _id: cid }, {products: selectedCart.products}); */
        await selectedCart.save()
        return selectedCart;
    }


    async deleteProduct(cid, pid){
        const selectedCart = await cartsModel.findById(cid)
        const productIndex = selectedCart.products.findIndex(p => p.product.equals(pid));
        const deletedProduct = selectedCart.products[productIndex]
        if (productIndex !== -1) {
            selectedCart.products.splice(productIndex, 1);
        }
        await selectedCart.save()
        return deletedProduct
    }


    async updateAllProducts(cid, arr){
        const selectedCart = await cartsModel.findById(cid)
        const newProducts = arr
        selectedCart.products = newProducts
        await selectedCart.save()
        return selectedCart
    }
    

    async updateProductQuantity(cid, pid, quant){
        const selectedCart = await cartsModel.findById(cid)
        const productIndex = selectedCart.products.findIndex(p => p.product.equals(pid));
        const newQuantity = quant
        if (productIndex !== -1) {
            selectedCart.products[productIndex].quantity = newQuantity
        }        
        await selectedCart.save()
        return selectedCart
    }

    async deleteAllProducts(cid){
        const selectedCart = await cartsModel.findById(cid)        
        selectedCart.products = []        
        await selectedCart.save()
        return selectedCart
    }
}


export const cManager = new CartsManager();