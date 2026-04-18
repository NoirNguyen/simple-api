require("dotenv").config();

const express = require("express");
const mysql = require("mysql2");
const bcrypt = require("bcryptjs");

const app = express();
app.use(express.json());

// 🔥 Quan trọng: cho phép serve file tĩnh
app.use(express.static("public"));


// 👉 Kết nối DB
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME
});

// API REGISTER
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Thiếu dữ liệu" });
  }

  try {
    // check email tồn tại chưa
    db.query(
      "SELECT * FROM users WHERE email = ? LIMIT 1",
      [email],
      async (err, results) => {
        if (err) {
          return res.status(500).json({ message: "Lỗi server" });
        }

        if (results.length > 0) {
          return res.status(400).json({ message: "Email đã tồn tại" });
        }

        // hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // insert user
        db.query(
          "INSERT INTO users (email, password) VALUES (?, ?)",
          [email, hashedPassword],
          (err) => {
            if (err) {
              return res.status(500).json({ message: "Lỗi tạo user" });
            }

            return res.json({ message: "Đăng ký thành công" });
          }
        );
      }
    );
  } catch (error) {
    return res.status(500).json({ message: "Lỗi server" });
  }
});


// 👉 API LOGIN (đơn giản nhất)
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ message: "Thiếu dữ liệu" });
  }

  db.query(
    "SELECT * FROM users WHERE email = ? LIMIT 1",
    [email],
    async (err, results) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: "Lỗi server" });
      }

      if (results.length === 0) {
        return res.status(400).json({ message: "Sai email hoặc mật khẩu" });
      }

      const user = results[0];

      const isMatch = await bcrypt.compare(password, user.password);

      if (!isMatch) {
        return res.status(400).json({ message: "Sai email hoặc mật khẩu" });
      }

      return res.json({
        message: "Đăng nhập thành công",
        user: {
          id: user.id,
          email: user.email
        }
      });
    }
  );
});

// 👉 chạy server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Server chạy tại http://localhost:" + PORT);
});
