package time_based

import future.keywords

# Time-based access restrictions for ZTA
default allow_access := false

# Business hours: 8 AM to 9 PM (20:59) UTC
is_business_hour := result {
    now := time.now_ns()
    hour := time.clock(now)[0]
    result := hour >= 8 and hour < 21
}

# Check if current time is within restricted hours (9 PM to 8 AM)
is_restricted_hour := result {
    now := time.now_ns()
    hour := time.clock(now)[0]
    result := hour >= 21 or hour < 8
}

# Weekend check
is_weekend := result {
    now := time.now_ns()
    day := time.weekday(now)
    result := day == "Saturday" or day == "Sunday"
}

# TOP_SECRET documents have strict time restrictions
top_secret_time_allowed := allowed {
    input.resource.classification == "TOP_SECRET"
    
    # TOP_SECRET can only be accessed during business hours
    allowed := is_business_hour
    not is_weekend  # No TOP_SECRET access on weekends
}

# SECRET documents have moderate restrictions
secret_time_allowed := allowed {
    input.resource.classification == "SECRET"
    
    # SECRET can be accessed during extended hours
    now := time.now_ns()
    hour := time.clock(now)[0]
    allowed := hour >= 6 and hour < 23  # 6 AM to 11 PM
    not is_weekend
}

# CONFIDENTIAL and BASIC have minimal time restrictions
confidential_time_allowed := true {
    input.resource.classification == "CONFIDENTIAL"
    not is_weekend  # No weekend access for CONFIDENTIAL
}

basic_time_allowed := true {
    input.resource.classification == "BASIC"
    # BASIC can be accessed anytime
}

# Main time-based policy evaluation
time_based_decision := decision {
    decision := {"allowed": false, "reason": "No time-based policy matched"}
} else := decision {
    input.resource.classification == "TOP_SECRET"
    top_secret_time_allowed
    decision := {"allowed": true, "reason": "TOP_SECRET access allowed during business hours"}
} else := decision {
    input.resource.classification == "TOP_SECRET"
    not top_secret_time_allowed
    decision := {"allowed": false, "reason": "TOP_SECRET access restricted outside business hours (8 AM - 9 PM)"}
} else := decision {
    input.resource.classification == "SECRET"
    secret_time_allowed
    decision := {"allowed": true, "reason": "SECRET access allowed"}
} else := decision {
    input.resource.classification == "SECRET"
    not secret_time_allowed
    decision := {"allowed": false, "reason": "SECRET access restricted (6 AM - 11 PM only)"}
} else := decision {
    input.resource.classification == "CONFIDENTIAL"
    confidential_time_allowed
    decision := {"allowed": true, "reason": "CONFIDENTIAL access allowed"}
} else := decision {
    input.resource.classification == "CONFIDENTIAL"
    not confidential_time_allowed
    decision := {"allowed": false, "reason": "CONFIDENTIAL access restricted on weekends"}
} else := decision {
    input.resource.classification == "BASIC"
    decision := {"allowed": true, "reason": "BASIC access always allowed"}
}

# Integrate with main ZTA policies
time_restricted_allow := allow {
    # First check if regular ZTA policies allow
    zta.allow
    
    # Then check time-based restrictions
    time_based_decision.allowed
}

# Enhanced decision with time context
enhanced_decision := {
    "allow": time_restricted_allow,
    "time_context": {
        "current_hour": time.clock(time.now_ns())[0],
        "current_weekday": time.weekday(time.now_ns()),
        "is_weekend": is_weekend,
        "is_business_hour": is_business_hour,
        "time_based_decision": time_based_decision,
        "restricted_hours_active": is_restricted_hour,
    },
    "zta_decision": zta.decision,
    "timestamp": time.now_ns(),
} {
    time_restricted_allow
} else := {
    "allow": false,
    "reason": time_based_decision.reason,
    "time_context": {
        "current_hour": time.clock(time.now_ns())[0],
        "current_weekday": time.weekday(time.now_ns()),
        "is_weekend": is_weekend,
        "is_business_hour": is_business_hour,
        "time_based_decision": time_based_decision,
        "restricted_hours_active": is_restricted_hour,
    },
    "zta_decision": zta.decision,
    "timestamp": time.now_ns(),
}