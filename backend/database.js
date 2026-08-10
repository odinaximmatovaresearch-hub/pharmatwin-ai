```javascript
const Database = require("better-sqlite3");

const db = new Database("pharmatwin.db");

db.pragma("foreign_keys = ON");

db.exec(`

CREATE TABLE IF NOT EXISTS patients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    phone TEXT,
    password_hash TEXT NOT NULL,
    date_of_birth TEXT,
    blood_type TEXT,
    oneid_connected INTEGER DEFAULT 0,
    consent_given INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS diseases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'monitoring',
    severity TEXT,
    diagnosed_at TEXT,
    notes TEXT,
    FOREIGN KEY(patient_id)
        REFERENCES patients(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS medications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    dose TEXT,
    frequency TEXT,
    purpose TEXT,
    start_date TEXT,
    end_date TEXT,
    status TEXT DEFAULT 'active',
    FOREIGN KEY(patient_id)
        REFERENCES patients(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS side_effects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    medication_id INTEGER,
    effect TEXT NOT NULL,
    severity TEXT,
    observed_at TEXT,
    notes TEXT,
    FOREIGN KEY(patient_id)
        REFERENCES patients(id)
        ON DELETE CASCADE,
    FOREIGN KEY(medication_id)
        REFERENCES medications(id)
        ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS lab_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    marker TEXT NOT NULL,
    value REAL,
    unit TEXT,
    reference_range TEXT,
    recorded_at TEXT,
    notes TEXT,
    FOREIGN KEY(patient_id)
        REFERENCES patients(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS treatment_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    event_date TEXT,
    FOREIGN KEY(patient_id)
        REFERENCES patients(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ai_insights (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id INTEGER NOT NULL,
    insight_type TEXT,
    title TEXT,
    description TEXT,
    confidence REAL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(patient_id)
        REFERENCES patients(id)
        ON DELETE CASCADE
);

`);

module.exports = db;
```
