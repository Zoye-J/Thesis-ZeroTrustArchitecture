package zta.main

import future.keywords

# ZTA Core Policies
default allow := false

#############################################
# AUTHENTICATION TIER SYSTEM
#############################################

# Authentication tiers (3 = strongest)
auth_tier := tier {
    # Tier 3: mTLS + JWT + Biometric (Future)
    input.auth.method == "mTLS_JWT_BIOMETRIC"
    tier := 3
} else := tier {
    # Tier 2: mTLS + JWT (Current implementation)
    input.auth.method == "mTLS_JWT"
    input.certificate.valid == true
    input.jwt.valid == true
    input.certificate.email == input.jwt.email
    tier := 2
} else := tier {
    # Tier 1: mTLS Service
    input.auth.method == "mTLS_service"
    input.certificate.valid == true
    valid_services[input.certificate.cn]
    tier := 1
} else := 0

# Valid services in ZTA ecosystem
valid_services["opa-agent.zta.gov"]
valid_services["api-server.zta.gov"]
valid_services["auth-service.zta.gov"]
valid_services["document-service.zta.gov"]

#############################################
# RISK-BASED ACCESS CONTROL
#############################################

# Calculate risk score
risk_score := score {
    # Higher clearance = higher risk if compromised
    clearance_risk := {
        "BASIC": 1,
        "CONFIDENTIAL": 2,
        "SECRET": 3,
        "TOP_SECRET": 4
    }[input.user.clearance]
    
    # Authentication strength reduces risk
    auth_mitigation := {
        3: 0.9,  # Strongest auth
        2: 0.7,  # Strong auth
        1: 0.4,  # Weak auth
        0: 0.0   # No auth
    }[auth_tier]
    
    # Time risk
    time_risk := 1.0 {
        input.time.hour >= 9
        input.time.hour <= 17
        not input.time.weekend
    } else := 1.5
    
    score := clearance_risk * time_risk * (1 - auth_mitigation)
}

# Allow if risk is acceptable
allow {
    auth_tier >= required_tier[input.resource.classification]
    risk_score <= max_risk_score[input.resource.classification]
}

# Required authentication tier per classification
required_tier["TOP_SECRET"] := 2  # mTLS + JWT
required_tier["SECRET"] := 2      # mTLS + JWT
required_tier["CONFIDENTIAL"] := 1 # mTLS service
required_tier["BASIC"] := 0       # Any

# Maximum risk scores
max_risk_score["TOP_SECRET"] := 1.0
max_risk_score["SECRET"] := 1.5
max_risk_score["CONFIDENTIAL"] := 2.0
max_risk_score["BASIC"] := 3.0

#############################################
# SERVICE MESH POLICIES
#############################################

# Service communication policies
allow_service_communication {
    input.source.type == "service"
    input.destination.type == "service"
    
    # Both must have valid certificates
    input.source.certificate.valid
    input.destination.certificate.valid
    
    # Communication matrix
    service_communication_allowed[input.source.name][input.destination.name]
}

# Service communication matrix
service_communication_allowed["opa-agent.zta.gov"]["api-server.zta.gov"]
service_communication_allowed["api-server.zta.gov"]["document-service.zta.gov"]
service_communication_allowed["auth-service.zta.gov"]["api-server.zta.gov"]
service_communication_allowed["document-service.zta.gov"]["api-server.zta.gov"]

# Transitive trust is NOT allowed (Zero Trust principle)
service_communication_allowed[source][destination] {
    # Explicitly list allowed communications
}

#############################################
# CERTIFICATE LIFECYCLE POLICIES
#############################################

# Certificate issuance
allow_certificate_issue {
    input.action == "issue_certificate"
    
    # Only specific roles can issue certificates
    input.requester.role == "superadmin"
    or input.requester.role == "admin"
    
    # Certificate type restrictions
    input.certificate.type == "user" {
        # Admins can only issue for their department
        input.requester.role == "admin"
        input.certificate.department == input.requester.department
    }
    
    input.certificate.type == "service" {
        # Only superadmins can issue service certificates
        input.requester.role == "superadmin"
    }
}

# Certificate revocation
allow_certificate_revoke {
    input.action == "revoke_certificate"
    
    # Can revoke own certificate
    input.certificate.email == input.requester.email
    
    # Or higher role can revoke
    role_hierarchy := {"user": 1, "admin": 2, "superadmin": 3}
    role_hierarchy[input.requester.role] > role_hierarchy[input.certificate.owner.role]
    
    # Or certificate is compromised
    input.reason == "compromised"
}


#############################################
# DEPARTMENT-SPECIFIC ACCESS CONTROL
#############################################

# Department resource mapping
department_resources := {
    "Ministry of Defence": {
        "departments": ["Operations", "Intelligence", "Logistics", "Personnel"],
        "categories": ["Strategy", "Operations", "Budget", "Personnel", "Intelligence", "Weapons"],
        "allowed_facilities": ["Ministry of Defence", "National Security Agency"]  # MOD can access some NSA docs
    },
    "Ministry of Finance": {
        "departments": ["Budget", "Taxation", "Treasury", "Audit"],
        "categories": ["Budget", "Finance", "Tax", "Policy", "Procurement"],
        "allowed_facilities": ["Ministry of Finance"]
    },
    "National Security Agency": {
        "departments": ["Cyber Security", "Intelligence", "Counter-Terrorism", "Surveillance"],
        "categories": ["Intelligence", "Security", "Technology", "Cyber", "Surveillance"],
        "allowed_facilities": ["National Security Agency", "Ministry of Defence"]  # NSA can access some MOD docs
    }
}

# Check if user can access resource based on department
department_access_allowed {
    # Get user's facility info
    user_facility := input.user.facility
    user_department := input.user.department
    
    # Get resource info
    resource_facility := input.resource.facility
    resource_department := input.resource.department
    resource_category := input.resource.category
    
    # User's facility mapping
    facility_config := department_resources[user_facility]
    
    # Check 1: User can access resources from allowed facilities
    facility_config.allowed_facilities[_] == resource_facility
    
    # Check 2: User can access resources from allowed departments
    facility_config.departments[_] == resource_department
    
    # Check 3: User can access resources from allowed categories (if category specified)
    resource_category == "" or facility_config.categories[_] == resource_category
}

#############################################
# ENHANCED CLEARANCE LEVEL CHECKS
#############################################

# Clearance level hierarchy
clearance_hierarchy := ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]

# Check if user has sufficient clearance
clearance_allowed {
    # Get indices in hierarchy
    user_index := {i | clearance_hierarchy[i] == input.user.clearance}
    resource_index := {i | clearance_hierarchy[i] == input.resource.classification}
    
    # User clearance must be >= resource clearance
    user_index[_] >= resource_index[_]
}

#############################################
# TIME-BASED ACCESS RESTRICTIONS
#############################################

# Business hours: 8 AM to 9 PM (20:59)
is_business_hour {
    hour := time.clock(time.now_ns())[0]
    hour >= 8
    hour < 21
}

# TOP_SECRET documents require business hours
top_secret_time_allowed {
    input.resource.classification != "TOP_SECRET"
} else {
    input.resource.classification == "TOP_SECRET"
    is_business_hour
}

#############################################
# AUTHENTICATION STRENGTH REQUIREMENTS
#############################################

# Authentication tiers
auth_tier := tier {
    # Tier 3: mTLS + JWT
    input.authentication.method == "mTLS_JWT"
    tier := 3
} else := tier {
    # Tier 2: mTLS Service
    input.authentication.method == "mTLS_service"
    tier := 2
} else := tier {
    # Tier 1: JWT only
    input.authentication.method == "JWT"
    tier := 1
} else := 0

# Required authentication tier based on classification
required_auth_tier := tier {
    input.resource.classification == "TOP_SECRET"
    tier := 2  # mTLS required
} else := tier {
    input.resource.classification == "SECRET"
    tier := 2  # mTLS required
} else := tier {
    input.resource.classification == "CONFIDENTIAL"
    tier := 1  # JWT acceptable
} else := 1

# Check authentication strength
auth_strength_allowed {
    auth_tier >= required_auth_tier
}

#############################################
# MAIN ACCESS DECISION
#############################################

# Grant access if ALL conditions are met
allow {
    # 1. Department access allowed
    department_access_allowed
    
    # 2. Clearance level sufficient
    clearance_allowed
    
    # 3. Time restrictions passed
    top_secret_time_allowed
    
    # 4. Authentication strength sufficient
    auth_strength_allowed
    
    # 5. Action is allowed for user role
    action_allowed
}

# Action-specific rules
action_allowed {
    input.action == "read"
} else {
    input.action == "create"
    input.user.role in ["admin", "superadmin"]
} else {
    input.action == "update"
    input.user.role in ["admin", "superadmin"]
    input.resource.owner == input.user.id  # Can only update own documents
} else {
    input.action == "delete"
    input.user.role == "superadmin"
}

#############################################
# DECISION WITH DETAILED REASONING
#############################################

decision := {
    "allow": allow,
    "reason": reason,
    "checks": {
        "department_access": department_access_allowed,
        "clearance": clearance_allowed,
        "time_restrictions": top_secret_time_allowed,
        "authentication": auth_strength_allowed,
        "action": action_allowed
    },
    "user_context": {
        "facility": input.user.facility,
        "department": input.user.department,
        "clearance": input.user.clearance,
        "role": input.user.role
    },
    "resource_context": {
        "facility": input.resource.facility,
        "department": input.resource.department,
        "classification": input.resource.classification,
        "category": input.resource.category
    },
    "timestamp": time.now_ns(),
    "request_id": input.request_id
} {
    allow
    reason := "Access granted - all policy checks passed"
} else = {
    "allow": false,
    "reason": reason,
    "failed_checks": failed_checks,
    "user_context": {
        "facility": input.user.facility,
        "department": input.user.department,
        "clearance": input.user.clearance,
        "role": input.user.role
    },
    "resource_context": {
        "facility": input.resource.facility,
        "department": input.resource.department,
        "classification": input.resource.classification,
        "category": input.resource.category
    },
    "timestamp": time.now_ns(),
    "request_id": input.request_id
} {
    not allow
    reason := "Access denied"
    failed_checks := {
        "department_access": not department_access_allowed,
        "clearance": not clearance_allowed,
        "time_restrictions": not top_secret_time_allowed,
        "authentication": not auth_strength_allowed,
        "action": not action_allowed
    }
}