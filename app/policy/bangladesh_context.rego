# app/policy/bangladesh_context.rego
package zta.bangladesh

# Bangladesh Government Structure
government_facilities := {
    "mod": "Ministry of Defence",
    "mof": "Ministry of Finance", 
    "nsa": "National Security Agency"
}

# Bangladesh Working Hours (UTC+6)
# Business hours in Bangladesh: 9 AM to 5 PM (Bangladesh time)
bangladesh_working_hours {
    # Convert UTC to Bangladesh Time (UTC+6)
    current_utc_hour := time.clock(time.now_ns())[0]
    bangladesh_hour := (current_utc_hour + 6) % 24
    
    # Check if within working hours (9 AM to 5 PM Bangladesh time)
    bangladesh_hour >= 9
    bangladesh_hour <= 17
}

# Bangladesh Holidays 2024
bangladesh_holidays := {
    "2024-02-21": "Language Martyrs' Day",
    "2024-03-17": "Birthday of Sheikh Mujibur Rahman",
    "2024-03-26": "Independence Day",
    "2024-04-14": "Bengali New Year",
    "2024-05-01": "May Day",
    "2024-12-16": "Victory Day",
    "2024-12-25": "Christmas Day"
}

# Check if today is a Bangladesh holiday
is_bangladesh_holiday {
    # Get current date in YYYY-MM-DD format
    current_date := time.format(time.now_ns(), "2006-01-02")
    bangladesh_holidays[current_date]
}

# Bangladesh Geographic Zones (simplified)
bangladesh_geo_zones := {
    "dhaka_government": ["103.15.0.0/16", "203.112.0.0/16"],  # Govt IP ranges
    "chattogram": ["103.16.0.0/16"],
    "outside_bangladesh": "HIGH_RISK_ZONE"
}

# Bangladesh Clearance Levels
bangladesh_clearance_hierarchy := ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]

# Time-based restrictions for Bangladesh
# TOP_SECRET documents only during working hours
allow_access_time_based {
    not is_bangladesh_holiday
    bangladesh_working_hours
} else = false {
    # Allow access to non-TOP_SECRET documents anytime
    input.resource.classification != "TOP_SECRET"
} else = false {
    # Deny TOP_SECRET access outside working hours
    input.resource.classification == "TOP_SECRET"
    not bangladesh_working_hours
}