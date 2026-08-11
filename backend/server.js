const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const multer = require("multer");
const Database = require("better-sqlite3");
const fs = require("fs");
const path = require("path");

const app = express();

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "CHANGE_THIS_SECRET";
const PUBLIC_APP_URL =
  process.env.PUBLIC_APP_URL || "http://localhost:3000";

const db = new Database(
  process.env.DB_PATH || "pharmatwin.db"
);

db.pragma("journal_mode = WAL");

app.use(
  helmet({
    crossOriginResourcePolicy: false
  })
);

app.use(
  cors({
    origin: true
  })
);

app.use(
  express.json({
    limit: "3mb"
  })
);

/* =========================
   UPLOADS
========================= */

const uploadDir = path.join(
  process.env.UPLOAD_DIR || ".",
  "uploads"
);

fs.mkdirSync(uploadDir, {
  recursive: true
});

const upload = multer({
  dest: uploadDir,

  limits: {
    fileSize: 5 * 1024 * 1024
  },

  fileFilter: (req, file, cb) => {
    if (file.mimetype === "application/pdf") {
      cb(null, true);
    } else {
      cb(
        new Error("Only PDF diploma files are allowed.")
      );
    }
  }
});

/* =========================
   DATABASE
========================= */

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,

  role TEXT NOT NULL
    CHECK(role IN ('patient','clinician','admin')),

  phone TEXT,

  verified INTEGER DEFAULT 0,

  diploma_filename TEXT,
  diploma_path TEXT,

  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS patients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  owner_user_id INTEGER,

  full_name TEXT NOT NULL,
  email TEXT,
  phone TEXT,

  jshshir TEXT UNIQUE NOT NULL,

  date_of_birth TEXT,
  sex TEXT,
  blood_group TEXT,

  allergies TEXT,

  status TEXT DEFAULT 'NEW',

  source TEXT DEFAULT 'PATIENT_SIGNUP',

  consent_status TEXT DEFAULT 'granted_self',

  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS diseases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  name TEXT NOT NULL,
  type TEXT,
  severity TEXT,

  diagnosed_at TEXT,

  notes TEXT
);

CREATE TABLE IF NOT EXISTS medications (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  name TEXT NOT NULL,

  dose TEXT,
  frequency TEXT,

  start_date TEXT,
  end_date TEXT,

  status TEXT DEFAULT 'active',

  positive_effects TEXT,
  side_effects TEXT,

  doctor_notes TEXT
);

CREATE TABLE IF NOT EXISTS labs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  test_name TEXT NOT NULL,

  value TEXT,
  unit TEXT,

  reference_range TEXT,

  measured_at TEXT,

  flag TEXT DEFAULT 'normal',

  notes TEXT
);

CREATE TABLE IF NOT EXISTS timeline (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  event_type TEXT NOT NULL,

  title TEXT NOT NULL,

  description TEXT,

  event_date TEXT
);

CREATE TABLE IF NOT EXISTS consent_requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  clinician_user_id INTEGER NOT NULL,

  jshshir TEXT NOT NULL,

  status TEXT DEFAULT 'pending',

  notification_text TEXT,

  consent_code_hash TEXT,

  consent_token_hash TEXT,

  notification_status TEXT DEFAULT 'not_sent',

  sms_id TEXT,
  sms_request_id TEXT,

  requested_at TEXT DEFAULT CURRENT_TIMESTAMP,

  responded_at TEXT
);

CREATE TABLE IF NOT EXISTS consents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  clinician_user_id INTEGER NOT NULL,

  consent_request_id INTEGER NOT NULL,

  status TEXT NOT NULL,

  granted_at TEXT DEFAULT CURRENT_TIMESTAMP,

  revoked_at TEXT
);

CREATE TABLE IF NOT EXISTS ai_signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  signal_type TEXT NOT NULL,

  title TEXT NOT NULL,

  severity TEXT DEFAULT 'info',

  summary TEXT,

  recommendation TEXT,

  created_at TEXT DEFAULT CURRENT_TIMESTAMP,

  reviewed_by INTEGER,

  reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS terminal_monitoring (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  patient_id INTEGER NOT NULL,

  condition TEXT NOT NULL,

  status TEXT,

  symptoms TEXT,

  care_plan TEXT,

  outcome_note TEXT,

  estimated_course TEXT,

  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,

  actor_user_id INTEGER,

  action TEXT NOT NULL,

  entity_type TEXT,

  entity_id INTEGER,

  metadata_json TEXT,

  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
`);

/* =========================
   HELPERS
========================= */

function hash(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function generateOTP() {
  return String(
    Math.floor(
      100000 + Math.random() * 900000
    )
  );
}

function generateToken() {
  return crypto.randomBytes(32).toString("hex");
}

function audit(
  actor,
  action,
  type,
  id,
  metadata = {}
) {
  db.prepare(`
    INSERT INTO audit_logs(
      actor_user_id,
      action,
      entity_type,
      entity_id,
      metadata_json
    )
    VALUES (?, ?, ?, ?, ?)
  `).run(
    actor || null,
    action,
    type || null,
    id || null,
    JSON.stringify(metadata)
  );
}

/* =========================
   AUTH
========================= */

function auth(req, res, next) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authentication required."
    });
  }

  try {
    req.user = jwt.verify(
      header.substring(7),
      JWT_SECRET
    );

    next();
  } catch {
    return res.status(401).json({
      message: "Session expired."
    });
  }
}

function allowRoles(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        message: "Permission denied."
      });
    }

    next();
  };
}

/* =========================
   DEVSMS
========================= */

async function devSmsRequest(
  endpoint,
  body
) {
  const token =
    process.env.SMS_API_TOKEN;

  if (!token) {
    throw new Error(
      "SMS_API_TOKEN is not configured."
    );
  }

  const response = await fetch(
    `https://devsms.uz/api/${endpoint}`,
    {
      method: "POST",

      headers: {
        "Authorization":
          `Bearer ${token}`,

        "Content-Type":
          "application/json"
      },

      body: JSON.stringify(body)
    }
  );

  const data =
    await response.json();

  if (!response.ok || data.success === false) {
    throw new Error(
      data.error ||
      data.message ||
      "DevSMS request failed."
    );
  }

  return data;
}

/*
  Consent SMS.

  We send the secure consent link
  and the OTP in the same normal SMS.
*/

async function sendConsentSMS(
  phone,
  consentLink,
  otp
) {
  const message =
`PharmaTwin AI
Patient data access request.

Approve or decline:
${consentLink}

Verification code:
${otp}

Do not share this code.`;

  return devSmsRequest(
    "send_sms.php",
    {
      phone: String(phone)
        .replace(/\D/g, ""),

      message,

      from:
        process.env.SMS_FROM || "4546",

      callback_url:
        process.env.SMS_CALLBACK_URL || undefined
    }
  );
}

/* =========================
   HEALTH
========================= */

app.get(
  "/api/health",
  (req, res) => {
    res.json({
      ok: true,
      service: "pharmatwin-ai",
      version: "7.0"
    });
  }
);

/* =========================
   REGISTER
========================= */

app.post(
  "/api/register",
  upload.single("diploma"),
  async (req, res) => {
    try {
      const {
        full_name,
        email,
        password,
        role = "patient",
        phone,
        jshshir
      } = req.body;

      if (
        !full_name ||
        !email ||
        !password
      ) {
        return res.status(400).json({
          message:
            "Name, email and password are required."
        });
      }

      if (
        !["patient", "clinician"]
          .includes(role)
      ) {
        return res.status(400).json({
          message: "Invalid role."
        });
      }

      if (
        role === "clinician" &&
        !req.file
      ) {
        return res.status(400).json({
          message:
            "Doctor diploma PDF is required."
        });
      }

      if (
        role === "patient" &&
        !/^\d{14}$/.test(
          jshshir || ""
        )
      ) {
        return res.status(400).json({
          message:
            "JSHSHIR must contain 14 digits."
        });
      }

      const normalizedEmail =
        email
          .trim()
          .toLowerCase();

      const exists =
        db.prepare(`
          SELECT id
          FROM users
          WHERE email = ?
        `).get(normalizedEmail);

      if (exists) {
        return res.status(409).json({
          message:
            "This email is already registered."
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const userId =
        db.prepare(`
          INSERT INTO users(
            full_name,
            email,
            password_hash,
            role,
            phone,
            verified,
            diploma_filename,
            diploma_path
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          full_name.trim(),
          normalizedEmail,
          passwordHash,
          role,
          phone || null,
          role === "patient"
            ? 1
            : 0,
          req.file?.originalname ||
            null,
          req.file?.path ||
            null
        ).lastInsertRowid;

      if (role === "patient") {
        db.prepare(`
          INSERT INTO patients(
            owner_user_id,
            full_name,
            email,
            phone,
            jshshir,
            status,
            source,
            consent_status
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          userId,
          full_name.trim(),
          normalizedEmail,
          phone || null,
          jshshir,
          "CONNECTED",
          "PATIENT_SIGNUP",
          "granted_self"
        );
      }

      audit(
        userId,
        "REGISTER",
        role,
        userId
      );

      res.status(201).json({
        message:
          role === "clinician"
            ? "Doctor registration submitted. Admin verification is required."
            : "Patient account created.",

        pending_verification:
          role === "clinician"
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message:
          error.message ||
          "Registration failed."
      });
    }
  }
);

/* =========================
   LOGIN
========================= */

app.post(
  "/api/login",
  async (req, res) => {

    const email =
      String(req.body.email || "")
        .trim()
        .toLowerCase();

    const password =
      String(
        req.body.password || ""
      );

    const user =
      db.prepare(`
        SELECT *
        FROM users
        WHERE email = ?
      `).get(email);

    if (
      !user ||
      !(await bcrypt.compare(
        password,
        user.password_hash
      ))
    ) {
      return res.status(401).json({
        message:
          "Incorrect email or password."
      });
    }

    if (
      user.role === "clinician" &&
      !user.verified
    ) {
      return res.status(403).json({
        message:
          "Doctor account is waiting for diploma verification."
      });
    }

    const sessionToken =
      jwt.sign(
        {
          id: user.id,
          full_name: user.full_name,
          email: user.email,
          role: user.role
        },
        JWT_SECRET,
        {
          expiresIn: "8h"
        }
      );

    audit(
      user.id,
      "LOGIN",
      "user",
      user.id
    );

    res.json({
      token: sessionToken,

      user: {
        id: user.id,
        full_name: user.full_name,
        email: user.email,
        role: user.role
      }
    });
  }
);

/* =========================
   CURRENT USER
========================= */

app.get(
  "/api/me",
  auth,
  (req, res) => {

    const user =
      db.prepare(`
        SELECT
          id,
          full_name,
          email,
          role,
          phone,
          verified
        FROM users
        WHERE id = ?
      `).get(req.user.id);

    res.json({
      user
    });
  }
);

/* =========================
   DOCTOR → PATIENT CONSENT
========================= */

app.post(
  "/api/consent-requests",
  auth,
  allowRoles("clinician"),
  async (req, res) => {

    try {

      const jshshir =
        String(
          req.body.jshshir || ""
        );

      if (
        !/^\d{14}$/.test(jshshir)
      ) {
        return res.status(400).json({
          message:
            "JSHSHIR must contain exactly 14 digits."
        });
      }

      const patient =
        db.prepare(`
          SELECT *
          FROM patients
          WHERE jshshir = ?
        `).get(jshshir);

      if (!patient) {
        return res.status(404).json({
          message:
            "Patient was not found."
        });
      }

      if (!patient.phone) {
        return res.status(400).json({
          message:
            "Patient does not have a registered phone number."
        });
      }

      const existing =
        db.prepare(`
          SELECT id
          FROM consent_requests
          WHERE patient_id = ?
          AND clinician_user_id = ?
          AND status = 'pending'
        `).get(
          patient.id,
          req.user.id
        );

      if (existing) {
        return res.status(409).json({
          message:
            "A consent request is already pending."
        });
      }

      const verificationCode =
        generateOTP();

      const consentToken =
        generateToken();

      const consentLink =
        `${PUBLIC_APP_URL.replace(
          /\/$/,
          ""
        )}/?consent=${consentToken}`;

      const requestId =
        db.prepare(`
          INSERT INTO consent_requests(
            patient_id,
            clinician_user_id,
            jshshir,
            notification_text,
            consent_code_hash,
            consent_token_hash
          )
          VALUES (?, ?, ?, ?, ?, ?)
        `).run(
          patient.id,
          req.user.id,
          jshshir,
          consentLink,
          hash(verificationCode),
          hash(consentToken)
        ).lastInsertRowid;

      let smsResult;

      try {

        smsResult =
          await sendConsentSMS(
            patient.phone,
            consentLink,
            verificationCode
          );

        const smsId =
          smsResult.data?.sms_id ||
          null;

        const requestIdFromSms =
          smsResult.data?.request_id ||
          null;

        db.prepare(`
          UPDATE consent_requests
          SET
            notification_status = 'sent',
            sms_id = ?,
            sms_request_id = ?
          WHERE id = ?
        `).run(
          smsId,
          requestIdFromSms,
          requestId
        );

        audit(
          req.user.id,
          "CONSENT_SMS_SENT",
          "consent_request",
          requestId,
          {
            sms_id: smsId,
            request_id:
              requestIdFromSms
          }
        );

        return res.status(201).json({
          ok: true,

          request_id:
            requestId,

          sms_status:
            smsResult.data?.status ||
            "sent",

          message:
            "Consent SMS was sent."
        });

      } catch (smsError) {

        db.prepare(`
          UPDATE consent_requests
          SET notification_status = 'failed'
          WHERE id = ?
        `).run(requestId);

        console.error(
          "DevSMS error:",
          smsError
        );

        return res.status(502).json({
          message:
            "Consent request was created, but SMS could not be delivered."
        });
      }

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message:
          "Could not create consent request."
      });
    }
  }
);

/* =========================
   PUBLIC CONSENT PAGE DATA
========================= */

app.get(
  "/api/consent/:token",
  (req, res) => {

    const request =
      db.prepare(`
        SELECT
          cr.id,
          cr.status,
          cr.requested_at,
          u.full_name AS clinician_name
        FROM consent_requests cr
        JOIN users u
          ON u.id =
             cr.clinician_user_id
        WHERE cr.consent_token_hash = ?
      `).get(
        hash(req.params.token)
      );

    if (!request) {
      return res.status(404).json({
        message:
          "Invalid or expired consent link."
      });
    }

    res.json({
      request_id: request.id,
      status: request.status,
      clinician_name:
        request.clinician_name,
      requested_at:
        request.requested_at
    });
  }
);

/* =========================
   CONSENT RESPONSE
========================= */

app.post(
  "/api/consent/:token/respond",
  (req, res) => {

    try {

      const {
        decision,
        code
      } = req.body;

      const request =
        db.prepare(`
          SELECT
            cr.*,
            p.id AS patient_id,
            p.jshshir
          FROM consent_requests cr
          JOIN patients p
            ON p.id =
               cr.patient_id
          WHERE cr.consent_token_hash = ?
        `).get(
          hash(req.params.token)
        );

      if (!request) {
        return res.status(404).json({
          message:
            "Invalid consent link."
        });
      }

      if (
        request.status !== "pending"
      ) {
        return res.status(409).json({
          message:
            "This request has already been answered."
        });
      }

      /* DECLINE */

      if (decision === "decline") {

        db.prepare(`
          UPDATE consent_requests
          SET
            status = 'declined',
            responded_at =
              CURRENT_TIMESTAMP
          WHERE id = ?
        `).run(request.id);

        db.prepare(`
          UPDATE patients
          SET consent_status = 'declined'
          WHERE id = ?
        `).run(
          request.patient_id
        );

        return res.json({
          status: "declined",

          data_imported:
            false,

          message:
            "Access request declined."
        });
      }

      /* AGREE */

      if (decision !== "agree") {
        return res.status(400).json({
          message:
            "Invalid decision."
        });
      }

      if (
        hash(
          String(code || "")
        ) !==
        request.consent_code_hash
      ) {
        return res.status(401).json({
          message:
            "Incorrect verification code."
        });
      }

      const transaction =
        db.transaction(() => {

          db.prepare(`
            UPDATE consent_requests
            SET
              status = 'approved',
              responded_at =
                CURRENT_TIMESTAMP
            WHERE id = ?
          `).run(
            request.id
          );

          db.prepare(`
            UPDATE patients
            SET
              consent_status = 'granted',
              status = 'CONNECTED'
            WHERE id = ?
          `).run(
            request.patient_id
          );

          const consentId =
            db.prepare(`
              INSERT INTO consents(
                patient_id,
                clinician_user_id,
                consent_request_id,
                status
              )
              VALUES (?, ?, ?, 'granted')
            `).run(
              request.patient_id,
              request.clinician_user_id,
              request.id
            ).lastInsertRowid;

          db.prepare(`
            INSERT INTO timeline(
              patient_id,
              event_type,
              title,
              description,
              event_date
            )
            VALUES (
              ?,
              'CONSENT',
              'Patient authorization granted',
              'Patient approved clinical data access.',
              CURRENT_DATE
            )
          `).run(
            request.patient_id
          );

          audit(
            request.clinician_user_id,
            "CONSENT_GRANTED",
            "consent",
            consentId,
            {
              patient_id:
                request.patient_id
            }
          );
        });

      transaction();

      res.json({
        status: "approved",

        data_imported:
          false,

        message:
          "Consent approved successfully."
      });

    } catch (error) {

      console.error(error);

      res.status(500).json({
        message:
          "Could not process consent."
      });
    }
  }
);

/* =========================
   SMS CALLBACK
========================= */

app.post(
  "/api/sms-callback",
  (req, res) => {

    const {
      sms_id,
      request_id,
      status
    } = req.body || {};

    if (
      sms_id ||
      request_id
    ) {

      db.prepare(`
        UPDATE consent_requests
        SET notification_status = ?
        WHERE
          sms_id = ?
          OR sms_request_id = ?
      `).run(
        status || "unknown",
        sms_id || "",
        request_id || ""
      );
    }

    res.json({
      ok: true
    });
  }
);

/* =========================
   SMS STATUS
========================= */

app.get(
  "/api/sms-status/:requestId",
  auth,
  allowRoles(
    "clinician",
    "admin"
  ),
  async (req, res) => {

    try {

      if (
        !process.env.SMS_API_TOKEN
      ) {
        return res.status(503).json({
          message:
            "SMS provider is not configured."
        });
      }

      const response =
        await fetch(
          `https://devsms.uz/api/get_status.php?request_id=${encodeURIComponent(
            req.params.requestId
          )}`,
          {
            headers: {
              Authorization:
                `Bearer ${process.env.SMS_API_TOKEN}`
            }
          }
        );

      const data =
        await response.json();

      res.status(
        response.ok ? 200 : 502
      ).json(data);

    } catch (error) {

      res.status(502).json({
        message:
          "Could not retrieve SMS status."
      });
    }
  }
);

/* =========================
   SMS BALANCE
========================= */

app.get(
  "/api/sms-balance",
  auth,
  allowRoles("admin"),
  async (req, res) => {

    try {

      const response =
        await fetch(
          "https://devsms.uz/api/get_balance.php",
          {
            headers: {
              Authorization:
                `Bearer ${process.env.SMS_API_TOKEN}`
            }
          }
        );

      const data =
        await response.json();

      res.status(
        response.ok ? 200 : 502
      ).json(data);

    } catch {

      res.status(502).json({
        message:
          "Could not retrieve SMS balance."
      });
    }
  }
);

/* =========================
   PATIENT DASHBOARD
========================= */

app.get(
  "/api/patient/me",
  auth,
  allowRoles("patient"),
  (req, res) => {

    const patient =
      db.prepare(`
        SELECT *
        FROM patients
        WHERE owner_user_id = ?
      `).get(req.user.id);

    if (!patient) {
      return res.status(404).json({
        message:
          "Patient profile not found."
      });
    }

    const diseases =
      db.prepare(`
        SELECT *
        FROM diseases
        WHERE patient_id = ?
        ORDER BY diagnosed_at DESC
      `).all(patient.id);

    const medications =
      db.prepare(`
        SELECT *
        FROM medications
        WHERE patient_id = ?
        ORDER BY start_date DESC
      `).all(patient.id);

    const labs =
      db.prepare(`
        SELECT *
        FROM labs
        WHERE patient_id = ?
        ORDER BY measured_at DESC
      `).all(patient.id);

    const timeline =
      db.prepare(`
        SELECT *
        FROM timeline
        WHERE patient_id = ?
        ORDER BY event_date DESC
      `).all(patient.id);

    const signals =
      db.prepare(`
        SELECT *
        FROM ai_signals
        WHERE patient_id = ?
        ORDER BY created_at DESC
      `).all(patient.id);

    res.json({
      patient,
      diseases,
      medications,
      labs,
      timeline,
      signals
    });
  }
);

/* =========================
   DOCTOR PATIENTS
========================= */

app.get(
  "/api/clinician/patients",
  auth,
  allowRoles("clinician"),
  (req, res) => {

    const patients =
      db.prepare(`
        SELECT DISTINCT p.*
        FROM patients p
        JOIN consent_requests c
          ON c.patient_id = p.id
        WHERE
          c.clinician_user_id = ?
          AND c.status = 'approved'
        ORDER BY p.created_at DESC
      `).all(req.user.id);

    res.json({
      patients
    });
  }
);

/* =========================
   PATIENT DETAIL
========================= */

app.get(
  "/api/clinician/patients/:id",
  auth,
  allowRoles("clinician"),
  (req, res) => {

    const allowed =
      db.prepare(`
        SELECT id
        FROM consent_requests
        WHERE
          patient_id = ?
          AND clinician_user_id = ?
          AND status = 'approved'
        LIMIT 1
      `).get(
        req.params.id,
        req.user.id
      );

    if (!allowed) {
      return res.status(403).json({
        message:
          "Active patient consent is required."
      });
    }

    const patient =
      db.prepare(`
        SELECT *
        FROM patients
        WHERE id = ?
      `).get(
        req.params.id
      );

    if (!patient) {
      return res.status(404).json({
        message:
          "Patient not found."
      });
    }

    const diseases =
      db.prepare(`
        SELECT *
        FROM diseases
        WHERE patient_id = ?
      `).all(patient.id);

    const medications =
      db.prepare(`
        SELECT *
        FROM medications
        WHERE patient_id = ?
      `).all(patient.id);

    const labs =
      db.prepare(`
        SELECT *
        FROM labs
        WHERE patient_id = ?
        ORDER BY measured_at DESC
      `).all(patient.id);

    const timeline =
      db.prepare(`
        SELECT *
        FROM timeline
        WHERE patient_id = ?
        ORDER BY event_date DESC
      `).all(patient.id);

    const signals =
      db.prepare(`
        SELECT *
        FROM ai_signals
        WHERE patient_id = ?
        ORDER BY created_at DESC
      `).all(patient.id);

    const terminal =
      db.prepare(`
        SELECT *
        FROM terminal_monitoring
        WHERE patient_id = ?
        ORDER BY updated_at DESC
      `).all(patient.id);

    res.json({
      patient,
      diseases,
      medications,
      labs,
      timeline,
      signals,
      terminal
    });
  }
);

/* =========================
   ADD MEDICATION
========================= */

app.post(
  "/api/clinician/patients/:id/medications",
  auth,
  allowRoles("clinician"),
  (req, res) => {

    const allowed =
      db.prepare(`
        SELECT id
        FROM consent_requests
        WHERE
          patient_id = ?
          AND clinician_user_id = ?
          AND status = 'approved'
        LIMIT 1
      `).get(
        req.params.id,
        req.user.id
      );

    if (!allowed) {
      return res.status(403).json({
        message:
          "Active consent required."
      });
    }

    const {
      name,
      dose,
      frequency,
      start_date,
      end_date,
      status,
      positive_effects,
      side_effects,
      doctor_notes
    } = req.body;

    if (!name) {
      return res.status(400).json({
        message:
          "Medication name is required."
      });
    }

    const id =
      db.prepare(`
        INSERT INTO medications(
          patient_id,
          name,
          dose,
          frequency,
          start_date,
          end_date,
          status,
          positive_effects,
          side_effects,
          doctor_notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.params.id,
        name,
        dose || null,
        frequency || null,
        start_date || null,
        end_date || null,
        status || "active",
        positive_effects || null,
        side_effects || null,
        doctor_notes || null
      ).lastInsertRowid;

    db.prepare(`
      INSERT INTO timeline(
        patient_id,
        event_type,
        title,
        description,
        event_date
      )
      VALUES (
        ?,
        'MEDICATION',
        ?,
        'Medication record updated by clinician.',
        CURRENT_DATE
      )
    `).run(
      req.params.id,
      `Medication: ${name}`
    );

    audit(
      req.user.id,
      "MEDICATION_CREATED",
      "medication",
      id
    );

    res.status(201).json({
      id
    });
  }
);

/* =========================
   ADD LAB
========================= */

app.post(
  "/api/clinician/patients/:id/labs",
  auth,
  allowRoles("clinician"),
  (req, res) => {

    const allowed =
      db.prepare(`
        SELECT id
        FROM consent_requests
        WHERE
          patient_id = ?
          AND clinician_user_id = ?
          AND status = 'approved'
        LIMIT 1
      `).get(
        req.params.id,
        req.user.id
      );

    if (!allowed) {
      return res.status(403).json({
        message:
          "Active consent required."
      });
    }

    const {
      test_name,
      value,
      unit,
      reference_range,
      measured_at,
      flag,
      notes
    } = req.body;

    if (!test_name) {
      return res.status(400).json({
        message:
          "Test name is required."
      });
    }

    const id =
      db.prepare(`
        INSERT INTO labs(
          patient_id,
          test_name,
          value,
          unit,
          reference_range,
          measured_at,
          flag,
          notes
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `).run(
        req.params.id,
        test_name,
        value || null,
        unit || null,
        reference_range || null,
        measured_at || null,
        flag || "normal",
        notes || null
      ).lastInsertRowid;

    res.status(201).json({
      id
    });
  }
);

/* =========================
   AI CLINICAL SIGNAL
========================= */

app.post(
  "/api/clinician/patients/:id/ai-signal",
  auth,
  allowRoles("clinician"),
  (req, res) => {

    const allowed =
      db.prepare(`
        SELECT id
        FROM consent_requests
        WHERE
          patient_id = ?
          AND clinician_user_id = ?
          AND status = 'approved'
        LIMIT 1
      `).get(
        req.params.id,
        req.user.id
      );

    if (!allowed) {
      return res.status(403).json({
        message:
          "Active consent required."
      });
    }

    const {
      signal_type,
      title,
      severity = "info",
      summary,
      recommendation
    } = req.body;

    const id =
      db.prepare(`
        INSERT INTO ai_signals(
          patient_id,
          signal_type,
          title,
          severity,
          summary,
          recommendation,
          reviewed_by,
          reviewed_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
      `).run(
        req.params.id,
        signal_type,
        title,
        severity,
        summary,
        recommendation,
        req.user.id
      ).lastInsertRowid;

    res.status(201).json({
      id,

      message:
        "Clinical decision-support signal saved for clinician review."
    });
  }
);

/* =========================
   ERROR HANDLER
========================= */

app.use(
  (error, req, res, next) => {

    console.error(error);

    res.status(400).json({
      message:
        error.message ||
        "Request failed."
    });
  }
);

/* =========================
   START
========================= */

app.listen(
  PORT,
  () => {
    console.log(
      `PharmaTwin AI running on port ${PORT}`
    );
  }
);
