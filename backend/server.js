const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("./database");

const app = express();

const PORT = process.env.PORT || 10000;
const JWT_SECRET = process.env.JWT_SECRET || "pharmatwin-development-secret";

app.use(cors());
app.use(express.json());


// =========================
// AUTH MIDDLEWARE
// =========================

function auth(req, res, next) {
    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {
        return res.status(401).json({
            error: "Authentication required"
        });
    }

    const token = header.split(" ")[1];

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.patientId = decoded.patientId;
        next();
    } catch (error) {
        return res.status(401).json({
            error: "Invalid or expired token"
        });
    }
}


// =========================
// HOME
// =========================

app.get("/", (req, res) => {
    res.json({
        name: "PharmaTwin AI API",
        status: "online",
        version: "1.0.0"
    });
});


// =========================
// HEALTH CHECK
// =========================

app.get("/api/health", (req, res) => {
    res.json({
        status: "healthy",
        database: "connected"
    });
});


// =========================
// REGISTER
// =========================

app.post("/api/auth/register", async (req, res) => {
    try {
        const {
            full_name,
            email,
            phone,
            password
        } = req.body;

        if (!full_name || !email || !password) {
            return res.status(400).json({
                error: "Full name, email and password are required"
            });
        }

        const existing = db
            .prepare("SELECT id FROM patients WHERE email = ?")
            .get(email);

        if (existing) {
            return res.status(409).json({
                error: "An account with this email already exists"
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);

        const result = db.prepare(
            "INSERT INTO patients (full_name, email, phone, password_hash) VALUES (?, ?, ?, ?)"
        ).run(
            full_name,
            email,
            phone || null,
            passwordHash
        );

        const token = jwt.sign(
            {
                patientId: result.lastInsertRowid
            },
            JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        res.status(201).json({
            message: "Registration successful",
            token: token,
            patient: {
                id: result.lastInsertRowid,
                full_name: full_name,
                email: email,
                phone: phone || null
            }
        });

    } catch (error) {
        console.error("REGISTER ERROR:", error);

        res.status(500).json({
            error: "Registration failed"
        });
    }
});


// =========================
// LOGIN
// =========================

app.post("/api/auth/login", async (req, res) => {
    try {
        const {
            email,
            password
        } = req.body;

        if (!email || !password) {
            return res.status(400).json({
                error: "Email and password are required"
            });
        }

        const patient = db
            .prepare("SELECT * FROM patients WHERE email = ?")
            .get(email);

        if (!patient) {
            return res.status(401).json({
                error: "Invalid email or password"
            });
        }

        const passwordCorrect = await bcrypt.compare(
            password,
            patient.password_hash
        );

        if (!passwordCorrect) {
            return res.status(401).json({
                error: "Invalid email or password"
            });
        }

        const token = jwt.sign(
            {
                patientId: patient.id
            },
            JWT_SECRET,
            {
                expiresIn: "7d"
            }
        );

        res.json({
            message: "Login successful",
            token: token,
            patient: {
                id: patient.id,
                full_name: patient.full_name,
                email: patient.email,
                phone: patient.phone
            }
        });

    } catch (error) {
        console.error("LOGIN ERROR:", error);

        res.status(500).json({
            error: "Login failed"
        });
    }
});


// =========================
// PATIENT PROFILE
// =========================

app.get("/api/patient/profile", auth, (req, res) => {
    const patient = db.prepare(
        "SELECT id, full_name, email, phone, date_of_birth, blood_type, oneid_connected, consent_given, created_at FROM patients WHERE id = ?"
    ).get(req.patientId);

    if (!patient) {
        return res.status(404).json({
            error: "Patient not found"
        });
    }

    res.json(patient);
});


app.put("/api/patient/profile", auth, (req, res) => {
    const {
        full_name,
        phone,
        date_of_birth,
        blood_type
    } = req.body;

    db.prepare(
        "UPDATE patients SET full_name = COALESCE(?, full_name), phone = COALESCE(?, phone), date_of_birth = COALESCE(?, date_of_birth), blood_type = COALESCE(?, blood_type) WHERE id = ?"
    ).run(
        full_name || null,
        phone || null,
        date_of_birth || null,
        blood_type || null,
        req.patientId
    );

    res.json({
        message: "Profile updated successfully"
    });
});


// =========================
// CONSENT
// =========================

app.post("/api/patient/consent", auth, (req, res) => {
    const { consent } = req.body;

    if (typeof consent !== "boolean") {
        return res.status(400).json({
            error: "Consent must be true or false"
        });
    }

    db.prepare(
        "UPDATE patients SET consent_given = ? WHERE id = ?"
    ).run(
        consent ? 1 : 0,
        req.patientId
    );

    res.json({
        message: "Consent status saved",
        consent: consent
    });
});


// =========================
// DISEASES
// =========================

app.get("/api/patient/diseases", auth, (req, res) => {
    const diseases = db.prepare(
        "SELECT * FROM diseases WHERE patient_id = ? ORDER BY diagnosed_at DESC"
    ).all(req.patientId);

    res.json(diseases);
});


app.post("/api/patient/diseases", auth, (req, res) => {
    const {
        name,
        status,
        severity,
        diagnosed_at,
        notes
    } = req.body;

    if (!name) {
        return res.status(400).json({
            error: "Disease name is required"
        });
    }

    const result = db.prepare(
        "INSERT INTO diseases (patient_id, name, status, severity, diagnosed_at, notes) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(
        req.patientId,
        name,
        status || "monitoring",
        severity || null,
        diagnosed_at || null,
        notes || null
    );

    res.status(201).json({
        id: result.lastInsertRowid,
        message: "Disease added successfully"
    });
});


// =========================
// MEDICATIONS
// =========================

app.get("/api/patient/medications", auth, (req, res) => {
    const medications = db.prepare(
        "SELECT * FROM medications WHERE patient_id = ? ORDER BY start_date DESC"
    ).all(req.patientId);

    res.json(medications);
});


app.post("/api/patient/medications", auth, (req, res) => {
    const {
        name,
        dose,
        frequency,
        purpose,
        start_date
    } = req.body;

    if (!name) {
        return res.status(400).json({
            error: "Medication name is required"
        });
    }

    const result = db.prepare(
        "INSERT INTO medications (patient_id, name, dose, frequency, purpose, start_date) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(
        req.patientId,
        name,
        dose || null,
        frequency || null,
        purpose || null,
        start_date || null
    );

    res.status(201).json({
        id: result.lastInsertRowid,
        message: "Medication added successfully"
    });
});


// =========================
// LAB RESULTS
// =========================

app.get("/api/patient/labs", auth, (req, res) => {
    const labs = db.prepare(
        "SELECT * FROM lab_results WHERE patient_id = ? ORDER BY recorded_at DESC"
    ).all(req.patientId);

    res.json(labs);
});


app.post("/api/patient/labs", auth, (req, res) => {
    const {
        marker,
        value,
        unit,
        reference_range,
        recorded_at,
        notes
    } = req.body;

    if (!marker) {
        return res.status(400).json({
            error: "Lab marker is required"
        });
    }

    const result = db.prepare(
        "INSERT INTO lab_results (patient_id, marker, value, unit, reference_range, recorded_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?)"
    ).run(
        req.patientId,
        marker,
        value ?? null,
        unit || null,
        reference_range || null,
        recorded_at || null,
        notes || null
    );

    res.status(201).json({
        id: result.lastInsertRowid,
        message: "Laboratory result added"
    });
});


// =========================
// SIDE EFFECTS
// =========================

app.get("/api/patient/side-effects", auth, (req, res) => {
    const effects = db.prepare(
        "SELECT side_effects.*, medications.name AS medication_name FROM side_effects LEFT JOIN medications ON medications.id = side_effects.medication_id WHERE side_effects.patient_id = ? ORDER BY observed_at DESC"
    ).all(req.patientId);

    res.json(effects);
});


app.post("/api/patient/side-effects", auth, (req, res) => {
    const {
        medication_id,
        effect,
        severity,
        observed_at,
        notes
    } = req.body;

    if (!effect) {
        return res.status(400).json({
            error: "Side effect is required"
        });
    }

    const result = db.prepare(
        "INSERT INTO side_effects (patient_id, medication_id, effect, severity, observed_at, notes) VALUES (?, ?, ?, ?, ?, ?)"
    ).run(
        req.patientId,
        medication_id || null,
        effect,
        severity || null,
        observed_at || null,
        notes || null
    );

    res.status(201).json({
        id: result.lastInsertRowid,
        message: "Side effect recorded"
    });
});


// =========================
// TREATMENT TIMELINE
// =========================

app.get("/api/patient/timeline", auth, (req, res) => {
    const events = db.prepare(
        "SELECT * FROM treatment_events WHERE patient_id = ? ORDER BY event_date DESC"
    ).all(req.patientId);

    res.json(events);
});


app.post("/api/patient/timeline", auth, (req, res) => {
    const {
        event_type,
        title,
        description,
        event_date
    } = req.body;

    if (!event_type || !title) {
        return res.status(400).json({
            error: "Event type and title are required"
        });
    }

    const result = db.prepare(
        "INSERT INTO treatment_events (patient_id, event_type, title, description, event_date) VALUES (?, ?, ?, ?, ?)"
    ).run(
        req.patientId,
        event_type,
        title,
        description || null,
        event_date || null
    );

    res.status(201).json({
        id: result.lastInsertRowid,
        message: "Timeline event added"
    });
});


// =========================
// AI INSIGHTS
// =========================

app.get("/api/ai/insights", auth, (req, res) => {
    const insights = db.prepare(
        "SELECT * FROM ai_insights WHERE patient_id = ? ORDER BY created_at DESC"
    ).all(req.patientId);

    res.json(insights);
});


app.post("/api/ai/analyze", auth, (req, res) => {

    const medications = db.prepare(
        "SELECT * FROM medications WHERE patient_id = ?"
    ).all(req.patientId);

    const diseases = db.prepare(
        "SELECT * FROM diseases WHERE patient_id = ?"
    ).all(req.patientId);

    const labs = db.prepare(
        "SELECT * FROM lab_results WHERE patient_id = ?"
    ).all(req.patientId);

    const sideEffects = db.prepare(
        "SELECT * FROM side_effects WHERE patient_id = ?"
    ).all(req.patientId);

    const insights = [];

    if (medications.length > 0) {
        insights.push({
            type: "medication",
            title: "Medication history detected",
            description: `${medications.length} medication record(s) available for analysis.`,
            confidence: 0.75
        });
    }

    if (diseases.length > 0) {
        insights.push({
            type: "disease",
            title: "Disease profile detected",
            description: `${diseases.length} condition(s) are recorded.`,
            confidence: 0.80
        });
    }

    if (labs.length > 0) {
        insights.push({
            type: "laboratory",
            title: "Laboratory data available",
            description: `${labs.length} laboratory result(s) can be monitored over time.`,
            confidence: 0.82
        });
    }

    if (sideEffects.length > 0) {
        insights.push({
            type: "side_effect",
            title: "Side-effect history detected",
            description: `${sideEffects.length} side-effect record(s) are available.`,
            confidence: 0.78
        });
    }

    if (insights.length === 0) {
        insights.push({
            type: "information",
            title: "More data needed",
            description: "Additional clinical data is required for meaningful analysis.",
            confidence: 0.95
        });
    }

    for (const insight of insights) {
        db.prepare(
            "INSERT INTO ai_insights (patient_id, insight_type, title, description, confidence) VALUES (?, ?, ?, ?, ?)"
        ).run(
            req.patientId,
            insight.type,
            insight.title,
            insight.description,
            insight.confidence
        );
    }

    res.json({
        patient_id: req.patientId,
        insights: insights,
        disclaimer: "PharmaTwin AI is a clinical decision-support prototype and does not replace a qualified healthcare professional."
    });
});


// =========================
// ERROR HANDLER
// =========================

app.use((err, req, res, next) => {
    console.error("SERVER ERROR:", err);

    res.status(500).json({
        error: "Internal server error"
    });
});


// =========================
// START SERVER
// =========================

app.listen(PORT, "0.0.0.0", () => {
    console.log("PharmaTwin API running on port " + PORT);
});
