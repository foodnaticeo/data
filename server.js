require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const multer = require("multer");
const crypto = require("crypto");
// Firebase Phone OTP is handled by the separate login backend.


const {
  createClient
} = require("@supabase/supabase-js");

// ENVIRONMENT VARIABLES
const required = [
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY"
];

for (const name of required) {
  if (!process.env[name]) {
    throw new Error(`Missing environment variable: ${name}`);
  }
}

// SUPABASE
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY,
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

// EXPRESS
const app = express();

const PORT = process.env.PORT || 3000;

const TABLE = "resturnatappplication";
const BUCKET = "restaurant-applications";

app.disable("x-powered-by");

app.use(helmet());

app.use(cors());

app.use(express.json({
  limit: "100kb"
}));

app.use("/api", rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

// HELPERS
function cleanText(value, max = 300) {
  if (typeof value !== "string") return null;

  return value.trim().slice(0, max);
}

function cleanObject(value) {
  if (
    value &&
    typeof value === "object" &&
    !Array.isArray(value)
  ) {
    return value;
  }

  return {};
}

function validId(id) {
  return /^[1-9]\d*$/.test(String(id));
}

function serverError(res, error, message) {
  console.error(message, error);

  return res.status(500).json({
    success: false,
    message
  });
}

// SUPABASE AUTH ADMIN CHECK
async function adminOnly(req, res, next) {
  try {
    const authorization =
      req.headers.authorization || "";

    const token = authorization.replace(
      /^Bearer\s+/i,
      ""
    );

    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Login required"
      });
    }

    const { data, error } =
      await supabase.auth.getUser(token);

    if (error || !data?.user) {
      return res.status(401).json({
        success: false,
        message: "Invalid login session"
      });
    }

    const user = data.user;

    if (user.app_metadata?.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Admin access required"
      });
    }

    req.adminUser = user;

    next();

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Authentication failed"
    });
  }
}

// Partner applications and uploads do not require a second OTP token check.

// Public Firebase web configuration (optional; OTP backend is separate).
app.get("/firebase-config", (req,res) => {
  if (!process.env.FIREBASE_WEB_CONFIG_JSON) return res.status(503).json({success:false,message:"Firebase web config not configured"});
  try {
    const c = JSON.parse(process.env.FIREBASE_WEB_CONFIG_JSON);
    const {apiKey,authDomain,projectId,appId,messagingSenderId,storageBucket} = c;
    if (!apiKey || !authDomain || !projectId || !appId) throw new Error("Missing Firebase web config fields");
    res.json({apiKey,authDomain,projectId,appId,messagingSenderId,storageBucket});
  } catch(e) { res.status(500).json({success:false,message:"Invalid Firebase web configuration"}); }
});

// HOME / HEALTH CHECK
app.get("/", (req, res) => {
  res.json({
    success: true,
    app: "Foodnati Restaurant API",
    status: "running",
    database: "Supabase"
  });
});

// CREATE RESTAURANT APPLICATION
app.post("/api/restaurant/apply", async (req, res) => {
  try {
    const b = req.body || {};

    const restaurant_name = cleanText(
      b.restaurant_name,
      200
    );

    const mobile_number = cleanText(
      b.mobile_number,
      20
    );

    if (!restaurant_name || !mobile_number) {
      return res.status(400).json({
        success: false,
        message: "Restaurant name and mobile required"
      });
    }

    if (!/^[+]?[0-9 -]{10,20}$/.test(mobile_number)) {
      return res.status(400).json({
        success: false,
        message: "Invalid mobile number"
      });
    }

    if (!Array.isArray(b.food_menu_images) || b.food_menu_images.length > 5 ||
        b.food_menu_images.some(p => typeof p !== "string" || !/^uploads\/[a-f0-9-]+\.(jpg|png|webp)$/.test(p))) {
      return res.status(400).json({ success: false, message: "Maximum five valid uploaded menu images allowed" });
    }
    const payload = {
      restaurant_name,

      owner_name: cleanText(
        b.owner_name,
        200
      ),

      mobile_number,

      food_menu_images:
        Array.isArray(b.food_menu_images)
          ? b.food_menu_images
              .filter(x => typeof x === "string")
              .slice(0, 5)
          : [],

      fssai_number: cleanText(
        b.fssai_number,
        30
      ),

      location: cleanObject(b.location),

      bank_account: cleanObject(
        b.bank_account
      ),

      pan_card: cleanObject(
        b.pan_card
      ),

      gst_number: cleanText(
        b.gst_number,
        30
      ),

      gst_certificate_url: cleanText(
        b.gst_certificate_url,
        1000
      ),

      restaurant_details: cleanObject(
        b.restaurant_details
      ),

      application_status: "pending"
    };

    const { data, error } = await supabase
      .from(TABLE)
      .insert(payload)
      .select(
        "id,restaurant_name,application_status,created_at"
      )
      .single();
if (error) {
      return serverError(res, error, "Application submission failed");
    }

    return res.status(201).json({
      success: true,
      message: "Application submitted successfully",
      application: data
    });

  } catch (error) {
    return serverError(
      res,
      error,
      "Application submission failed"
    );
  }
});

// GET ALL RESTAURANT APPLICATIONS
app.get(
  "/api/restaurant/applications",
  adminOnly,
  async (req, res) => {
    try {
      const page = Math.max(
        1,
        parseInt(req.query.page, 10) || 1
      );

      const limit = Math.min(
        50,
        Math.max(
          1,
          parseInt(req.query.limit, 10) || 20
        )
      );

      const start = (page - 1) * limit;

      const { data, error, count } =
        await supabase
          .from(TABLE)
          .select("*", {
            count: "exact"
          })
          .order("created_at", {
            ascending: false
          })
          .range(
            start,
            start + limit - 1
          );

      if (error) {
        return serverError(
          res,
          error,
          "Failed to load applications"
        );
      }

      return res.json({
        success: true,
        total: count,
        page,
        applications: data
      });

    } catch (error) {
      return serverError(
        res,
        error,
        "Failed to load applications"
      );
    }
  }
);

// GET SINGLE APPLICATION
app.get(
  "/api/restaurant/application/:id",
  adminOnly,
  async (req, res) => {
    try {
      const id = req.params.id;

      if (!validId(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid application ID"
        });
      }

      const { data, error } = await supabase
        .from(TABLE)
        .select("*")
        .eq("id", id)
        .maybeSingle();

      if (error) {
        return serverError(
          res,
          error,
          "Failed to load application"
        );
      }

      if (!data) {
        return res.status(404).json({
          success: false,
          message: "Application not found"
        });
      }

      return res.json({
        success: true,
        application: data
      });

    } catch (error) {
      return serverError(
        res,
        error,
        "Failed to load application"
      );
    }
  }
);

// UPDATE APPLICATION STATUS
app.patch(
  "/api/restaurant/application/:id/status",
  adminOnly,
  async (req, res) => {
    try {
      const id = req.params.id;

      if (!validId(id)) {
        return res.status(400).json({
          success: false,
          message: "Invalid application ID"
        });
      }

      const status =
        req.body?.application_status;

      const allowed = [
        "pending",
        "approved",
        "rejected"
      ];

      if (!allowed.includes(status)) {
        return res.status(400).json({
          success: false,
          message: "Invalid application status"
        });
      }

      const updates = {
        application_status: status,

        rejection_reason:
          status === "rejected"
            ? cleanText(
                req.body.rejection_reason,
                500
              )
            : null,

        updated_at:
          new Date().toISOString()
      };

      const { data, error } = await supabase
        .from(TABLE)
        .update(updates)
        .eq("id", id)
        .select(
          "id,application_status,updated_at"
        )
        .maybeSingle();

      if (error) {
        return serverError(
          res,
          error,
          "Failed to update status"
        );
      }

      if (!data) {
        return res.status(404).json({
          success: false,
          message: "Application not found"
        });
      }

      return res.json({
        success: true,
        message: "Status updated successfully",
        application: data
      });

    } catch (error) {
      return serverError(
        res,
        error,
        "Failed to update status"
      );
    }
  }
);

// FILE UPLOAD SETTINGS
const mimeToExt = {
  "image/jpeg": "jpg",
  "image/png": "png",
  "image/webp": "webp",
  "application/pdf": "pdf"
};

const upload = multer({
  storage: multer.memoryStorage(),

  limits: {
    fileSize: 10 * 1024 * 1024
  },

  fileFilter(req, file, cb) {
    cb(
      null,
      Boolean(mimeToExt[file.mimetype])
    );
  }
});

// UPLOAD RESTAURANT DOCUMENT
app.post(
  "/api/restaurant/upload",
  upload.single("file"),
  async (req, res) => {
    try {
      if (!req.file) {
        return res.status(400).json({
          success: false,
          message: "Valid file required"
        });
      }

      const extension =
        mimeToExt[req.file.mimetype];

      // Menu image uploads only; private files are stored by path, not public URL.
      if (!req.file.mimetype.startsWith("image/")) {
        return res.status(400).json({ success: false, message: "Menu images only" });
      }
      const path =
        `uploads/${crypto.randomUUID()}.${extension}`;

      const { error } = await supabase.storage
        .from(BUCKET)
        .upload(
          path,
          req.file.buffer,
          {
            contentType: req.file.mimetype,
            upsert: false
          }
        );

      if (error) {
        console.error("SUPABASE STORAGE ERROR:", error);
        return res.status(500).json({
          success: false,
          message: "File upload failed",
          error: error.message,
          code: error.statusCode || error.code || null
        });
      }

      return res.status(201).json({
        success: true,
        message: "File uploaded successfully",
        bucket: BUCKET,
        path
      });

    } catch (error) {
      return serverError(
        res,
        error,
        "File upload failed"
      );
    }
  }
);

// GET PRIVATE DOCUMENT URL
app.get(
  "/api/restaurant/file",
  adminOnly,
  async (req, res) => {
    try {
      const path = req.query.path;

      if (
        typeof path !== "string" ||
        !/^uploads\/[a-f0-9-]+\.(jpg|png|webp|pdf)$/.test(path)
      ) {
        return res.status(400).json({
          success: false,
          message: "Invalid file path"
        });
      }

      const { data, error } =
        await supabase.storage
          .from(BUCKET)
          .createSignedUrl(path, 300);

      if (error) {
        return serverError(
          res,
          error,
          "Failed to get document"
        );
      }

      return res.json({
        success: true,
        url: data.signedUrl,
        expires_in: 300
      });

    } catch (error) {
      return serverError(
        res,
        error,
        "Failed to get document"
      );
    }
  }
);

// ERROR HANDLER
app.use((err, req, res, next) => {
  console.error(err);

  res.status(400).json({
    success: false,
    message: "Invalid request or upload"
  });
});

// START SERVER
app.listen(PORT, "0.0.0.0", () => {
  console.log(
    `Foodnati Restaurant API running on port ${PORT}`
  );
});
