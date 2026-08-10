```javascript
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const db = require("./database");

const app = express();

const PORT = process.env.PORT || 3000;

const JWT_SECRET =
    process.env.JWT_SECRET || "CHANGE_THIS_IN_PRODUCTION";


/* ================= MIDDLEWARE ================= */

app.use(cors());

app.use(express.json());


/* ================= AUTH ================= */

function authenticate(req, res, next) {

    const header = req.headers.authorization;

    if (!header || !header.startsWith("Bearer ")) {

        return res.status(401).json({
            error: "Authentication required"
        });

    }

    const token = header.split(" ")[1];

    try {

        const decoded = jwt.verify(
            token,
            JWT_SECRET
        );

        req.patientId = decoded.patientId;

        next();

    } catch {

        return res.status(401).json({
            error: "Invalid or expired token"
        });

    }
}


/* ================= HEALTH CHECK ================= */

app.get("/", (req, res) => {

    res.json({
        name: "PharmaTwin AI API",
        version: "1.0.0",
        status: "running"
    });

});


/* ================= REGISTER ================= */

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
                error:
                    "Full name, email and password are required"
            });

        }


        const existing =
            db.prepare(
                "SELECT id FROM patients WHERE email = ?"
            ).get(email);


        if (existing) {

            return res.status(409).json({
                error: "Account already exists"
            });

        }


        const password_hash =
            await bcrypt.hash(password, 12);


        const result =
            db.prepare(`

                INSERT INTO patients
                (
                    full_name,
                    email,
                    phone,
                    password_hash
                )

                VALUES (?, ?, ?, ?)

            `).run(
                full_name,
                email,
                phone || null,
                password_hash
            );


        const token =
            jwt.sign(
                {
                    patientId: result.lastInsertRowid
                },
                JWT_SECRET,
                {
                    expiresIn: "7d"
                }
            );


        res.status(201).json({

            message: "Account created",

            token,

            patient: {

                id: result.lastInsertRowid,

                full_name,

                email,

                phone

            }

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Registration failed"
        });

    }

});


/* ================= LOGIN ================= */

app.post("/api/auth/login", async (req, res) => {

    try {

        const {
            email,
            password
        } = req.body;


        const patient =
            db.prepare(
                "SELECT * FROM patients WHERE email = ?"
            ).get(email);


        if (!patient) {

            return res.status(401).json({
                error: "Invalid email or password"
            });

        }


        const valid =
            await bcrypt.compare(
                password,
                patient.password_hash
            );


        if (!valid) {

            return res.status(401).json({
                error: "Invalid email or password"
            });

        }


        const token =
            jwt.sign(
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

            token,

            patient: {

                id: patient.id,

                full_name: patient.full_name,

                email: patient.email,

                phone: patient.phone

            }

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: "Login failed"
        });

    }

});


/* ================= PATIENT PROFILE ================= */

app.get(
    "/api/patient/profile",
    authenticate,
    (req, res) => {

        const patient =
            db.prepare(`

                SELECT
                    id,
                    full_name,
                    email,
                    phone,
                    date_of_birth,
                    blood_type,
                    oneid_connected,
                    consent_given,
                    created_at

                FROM patients

                WHERE id = ?

            `).get(req.patientId);


        if (!patient) {

            return res.status(404).json({
                error: "Patient not found"
            });

        }


        res.json(patient);

    }
);


/* ================= UPDATE PROFILE ================= */

app.put(
    "/api/patient/profile",
    authenticate,
    (req, res) => {

        const {
            full_name,
            phone,
            date_of_birth,
            blood_type
        } = req.body;


        db.prepare(`

            UPDATE patients

            SET
                full_name = COALESCE(?, full_name),
                phone = COALESCE(?, phone),
                date_of_birth =
                    COALESCE(?, date_of_birth),
                blood_type =
                    COALESCE(?, blood_type)

            WHERE id = ?

        `).run(
            full_name,
            phone,
            date_of_birth,
            blood_type,
            req.patientId
        );


        res.json({
            message: "Profile updated"
        });

    }
);


/* ================= CONSENT ================= */

app.post(
    "/api/patient/consent",
    authenticate,
    (req, res) => {

        const {
            consent
        } = req.body;


        if (typeof consent !== "boolean") {

            return res.status(400).json({
                error: "Consent must be true or false"
            });

        }


        db.prepare(`

            UPDATE patients

            SET consent_given = ?

            WHERE id = ?

        `).run(
            consent ? 1 : 0,
            req.patientId
        );


        res.json({

            message:
                consent
                    ? "Consent recorded"
                    : "Consent declined",

            consent

        });

    }
);


/* ================= ONEID STATUS ================= */

app.post(
    "/api/patient/oneid",
    authenticate,
    (req, res) => {

        /*
         * DEMO ONLY.
         *
         * Real OneID integration must happen here
         * through the official authentication flow.
         */

        const {
            connected
        } = req.body;


        db.prepare(`

            UPDATE patients

            SET oneid_connected = ?

            WHERE id = ?

        `).run(
            connected ? 1 : 0,
            req.patientId
        );


        res.json({

            message:
                "OneID status updated in demo mode",

            oneid_connected:
                Boolean(connected)

        });

    }
);


/* ================= DISEASES ================= */

app.get(
    "/api/patient/diseases",
    authenticate,
    (req, res) => {

        const diseases =
            db.prepare(`

                SELECT *

                FROM diseases

                WHERE patient_id = ?

                ORDER BY diagnosed_at DESC

            `).all(req.patientId);


        res.json(diseases);

    }
);


app.post(
    "/api/patient/diseases",
    authenticate,
    (req, res) => {

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


        const result =
            db.prepare(`

                INSERT INTO diseases
                (
                    patient_id,
                    name,
                    status,
                    severity,
                    diagnosed_at,
                    notes
                )

                VALUES (?, ?, ?, ?, ?, ?)

            `).run(
                req.patientId,
                name,
                status || "monitoring",
                severity || null,
                diagnosed_at || null,
                notes || null
            );


        res.status(201).json({

            id: result.lastInsertRowid,

            message: "Disease added"

        });

    }
);


/* ================= MEDICATIONS ================= */

app.get(
    "/api/patient/medications",
    authenticate,
    (req, res) => {

        const medications =
            db.prepare(`

                SELECT *

                FROM medications

                WHERE patient_id = ?

                ORDER BY start_date DESC

            `).all(req.patientId);


        res.json(medications);

    }
);


app.post(
    "/api/patient/medications",
    authenticate,
    (req, res) => {

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


        const result =
            db.prepare(`

                INSERT INTO medications
                (
                    patient_id,
                    name,
                    dose,
                    frequency,
                    purpose,
                    start_date
                )

                VALUES (?, ?, ?, ?, ?, ?)

            `).run(
                req.patientId,
                name,
                dose || null,
                frequency || null,
                purpose || null,
                start_date || null
            );


        res.status(201).json({

            id: result.lastInsertRowid,

            message: "Medication added"

        });

    }
);


/* ================= SIDE EFFECTS ================= */

app.get(
    "/api/patient/side-effects",
    authenticate,
    (req, res) => {

        const effects =
            db.prepare(`

                SELECT
                    side_effects.*,
                    medications.name AS medication_name

                FROM side_effects

                LEFT JOIN medications
                ON medications.id =
                   side_effects.medication_id

                WHERE side_effects.patient_id = ?

                ORDER BY observed_at DESC

            `).all(req.patientId);


        res.json(effects);

    }
);


app.post(
    "/api/patient/side-effects",
    authenticate,
    (req, res) => {

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


        const result =
            db.prepare(`

                INSERT INTO side_effects
                (
                    patient_id,
                    medication_id,
                    effect,
                    severity,
                    observed_at,
                    notes
                )

                VALUES (?, ?, ?, ?, ?, ?)

            `).run(
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

    }
);


/* ================= LAB RESULTS ================= */

app.get(
    "/api/patient/labs",
    authenticate,
    (req, res) => {

        const labs =
            db.prepare(`

                SELECT *

                FROM lab_results

                WHERE patient_id = ?

                ORDER BY recorded_at DESC

            `).all(req.patientId);


        res.json(labs);

    }
);


app.post(
    "/api/patient/labs",
    authenticate,
    (req, res) => {

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


        const result =
            db.prepare(`

                INSERT INTO lab_results
                (
                    patient_id,
                    marker,
                    value,
                    unit,
                    reference_range,
                    recorded_at,
                    notes
                )

                VALUES (?, ?, ?, ?, ?, ?, ?)

            `).run(
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

            message: "Lab result added"

        });

    }
);


/* ================= TIMELINE ================= */

app.get(
    "/api/patient/timeline",
    authenticate,
    (req, res) => {

        const events =
            db.prepare(`

                SELECT *

                FROM treatment_events

                WHERE patient_id = ?

                ORDER BY event_date DESC

            `).all(req.patientId);


        res.json(events);

    }
);


app.post(
    "/api/patient/timeline",
    authenticate,
    (req, res) => {

        const {
            event_type,
            title,
            description,
            event_date
        } = req.body;


        if (!event_type || !title) {

            return res.status(400).json({
                error:
                    "event_type and title are required"
            });

        }


        const result =
            db.prepare(`

                INSERT INTO treatment_events
                (
                    patient_id,
                    event_type,
                    title,
                    description,
                    event_date
                )

                VALUES (?, ?, ?, ?, ?)

            `).run(
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

    }
);


/* ================= AI ================= */

app.post(
    "/api/ai/analyze",
    authenticate,
    (req, res) => {

        const patientId =
            req.patientId;


        const medications =
            db.prepare(`

                SELECT *

                FROM medications

                WHERE patient_id = ?

            `).all(patientId);


        const labs =
            db.prepare(`

                SELECT *

                FROM lab_results

                WHERE patient_id = ?

                ORDER BY recorded_at DESC

            `).all(patientId);


        const diseases =
            db.prepare(`

                SELECT *

                FROM diseases

                WHERE patient_id = ?

            `).all(patientId);


        /*
         * This is a RULE-BASED DEMO.
         *
         * Later this endpoint can connect to a
         * validated clinical AI/ML system.
         */

        const insights = [];


        if (medications.length > 0) {

            insights.push({

                type: "medication",

                title:
                    "Treatment data available",

                description:
                    `${medications.length} medication(s) are currently recorded.`,

                confidence: 0.75

            });

        }


        if (labs.length > 0) {

            insights.push({

                type: "laboratory",

                title:
                    "Laboratory history available",

                description:
                    `${labs.length} laboratory result(s) are available for trend analysis.`,

                confidence: 0.80

            });

        }


        if (diseases.length > 0) {

            insights.push({

                type: "condition",

                title:
                    "Condition monitoring active",

                description:
                    `${diseases.length} condition(s) are recorded in the patient profile.`,

                confidence: 0.78

            });

        }


        if (insights.length === 0) {

            insights.push({

                type: "information",

                title:
                    "Insufficient data",

                description:
                    "More patient data is required before meaningful pattern analysis can be performed.",

                confidence: 0.95

            });

        }


        for (const insight of insights) {

            db.prepare(`

                INSERT INTO ai_insights
                (
                    patient_id,
                    insight_type,
                    title,
                    description,
                    confidence
                )

                VALUES (?, ?, ?, ?, ?)

            `).run(
                patientId,
                insight.type,
                insight.title,
                insight.description,
                insight.confidence
            );

        }


        res.json({

            patient_id: patientId,

            insights,

            disclaimer:
                "This prototype provides decision-support signals only and does not replace qualified clinical judgment."

        });

    }
);


/* ================= AI HISTORY ================= */

app.get(
    "/api/ai/insights",
    authenticate,
    (req, res) => {

        const insights =
            db.prepare(`

                SELECT *

                FROM ai_insights

                WHERE patient_id = ?

                ORDER BY created_at DESC

            `).all(req.patientId);


        res.json(insights);

    }
);


/* ================= ERROR HANDLER ================= */

app.use((err, req, res, next) => {

    console.error(err);

    res.status(500).json({

        error:
            "Internal server error"

    });

});


/* ================= START ================= */

app.listen(PORT, () => {

    console.log(
        `PharmaTwin API running on port ${PORT}`
    );

});
```
