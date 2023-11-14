import { Router } from "express";

const router = Router();

//cookie
// router.post("/", (req, res) => {
//   const { email } = req.body;
//   res.cookie("user", email, { maxAge: 10000 }).send("Cookie created");
// });

//session
router.post("/", (req, res) => {
  const { name, email } = req.body;
  req.session.name = name;
  req.session.email = email;
  res.send("session");
});

router.get("/view", (req, res) => {
  console.log(req);
  res.send("View cookie");
});
export default router;