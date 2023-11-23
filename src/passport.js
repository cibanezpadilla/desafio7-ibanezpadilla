import passport from "passport";
import { uManager } from "./dao/managersMongo/usersManager.js";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GithubStrategy } from "passport-github2";
import { hashData, compareData } from "./utils.js";
import { usersModel } from "./db/models/users.model.js";

// local

passport.use(
  "signup",
  new LocalStrategy(
    { passReqToCallback: true, usernameField: "email" },
    async (req, email, password, done) => {
      const { first_name, last_name } = req.body;
      if (!first_name || !last_name || !email || !password) {
        return done(null, false);      
      }
      try {
        let isAdmin
        if (email === "adminCoder@coder.com"){
          isAdmin = true
        }else{
          isAdmin = false
        }
        const hashedPassword = await hashData(password);
        const createdUser = await uManager.createUser({
          ...req.body,
          password: hashedPassword, isAdmin
        });
        done(null, createdUser);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.use(
  "login",
  new LocalStrategy(
    { usernameField: "email" },
    async (email, password, done) => {
      if (!email || !password) {
        done(null, false);
      }
      try {
        const user = await uManager.findUserByEmail(email);
        if (!user) {
          done(null, false);
        }
        const isPasswordValid = await compareData(password, user.password);
        if (!isPasswordValid) {
          return done(null, false);
        }         
        done(null, user);
        console.log(user)
      } catch (error) {
        done(error);
      }
    }
  )
);

// github
passport.use(
  "github",
  new GithubStrategy(
    {
      clientID: "Iv1.056daf57e629e2ed",
      clientSecret: "08795fc34594aacb35c5844298546f6c1405f6f8",
      callbackURL: "http://localhost:8080/api/sessions/callback",
      scope: ["user:email"]
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const userDB = await uManager.findUserByEmail(profile.emails[0].value);
        /* console.log(profile) */
        // login
        if (userDB) {
          if (userDB.isGithub) {
            return done(null, userDB);
          } else {
            return done(null, false);
          }
        }
        // signup
        const infoUser = {
          first_name: profile._json.name.split(" ")[0], // ['farid','sesin']
          last_name: profile._json.name.split(" ")[1],
          email: profile.emails[0].value,
          password: " ",
          isGithub: true,
        };
        const createdUser = await uManager.createUser(infoUser);
        done(null, createdUser);
      } catch (error) {
        done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  // _id
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await uManager.findUserByID(id);
    done(null, user);
  } catch (error) {
    done(error);
  }
});