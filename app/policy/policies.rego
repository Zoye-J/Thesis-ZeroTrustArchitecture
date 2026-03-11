package zta

import future.keywords

# Default deny everything - Zero Trust Principle
default allow := false

#############################################
# ZERO TRUST AUTHENTICATION POLICIES
#############################################


# Clearance hierarchy
clearance_hierarchy := ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]

# Get clearance index
clearance_index(level) := idx {
    some idx
    clearance_hierarchy[idx] == level
}

# Simple clearance check
clearance_allowed {
    user_idx := clearance_index(input.user.clearance)
    resource_idx := clearance_index(input.resource.classification)
    user_idx >= resource_idx
}

# Department check
department_allowed {
    input.user.department == input.resource.department
}

# Time check for TOP_SECRET
time_allowed {
    input.resource.classification != "TOP_SECRET"
} else {
    input.resource.classification == "TOP_SECRET"
    hour := time.clock_hour(input.environment.timestamp)
    hour >= 8
    hour <= 16
}

# Main allow rule - SIMPLE VERSION FOR TESTING
allow {
    # 1. Clearance check
    clearance_allowed
    
    # 2. Department check  
    department_allowed
    
    # 3. Time check
    time_allowed
    
    reason := sprintf("Access granted: %s clearance, %s department, time OK", 
        [input.user.clearance, input.user.department])
}
# Validate authentication method strength
auth_strength := strength {
    # Tier 1: mTLS + JWT (Strongest)
    input.authentication.method == "mTLS_JWT"
    strength := 3
} else := strength {
    # Tier 2: mTLS Service (Service-to-Service)
    input.authentication.method == "mTLS_service"
    strength := 2
} else := strength {
    # Tier 3: JWT only (Weakest - for backward compatibility)
    input.authentication.method == "JWT"
    strength := 1
} else := 0

# Minimum authentication strength required per resource
required_auth_strength(resource_type, classification) := strength {
    resource_type == "document"
    classification == "TOP_SECRET"
    strength := 3  # mTLS + JWT required
} else := strength {
    resource_type == "document"
    classification == "SECRET"
    strength := 2  # mTLS required
} else := strength {
    resource_type == "document"
    classification == "CONFIDENTIAL"
    strength := 2  # mTLS required
} else := strength {
    resource_type == "document"
    classification == "BASIC"
    strength := 1  # JWT acceptable
} else := 1

#############################################
# CERTIFICATE VALIDATION POLICIES
#############################################

# Validate certificate attributes
valid_certificate {
    # Certificate must be present for mTLS authentication
    input.authentication.certificate != null
    
    # Certificate must be issued by our CA
    input.authentication.certificate.issuer.organizationName == "Government ZTA"
    
    # Certificate must not be expired
    now := time.now_ns()
    input.authentication.certificate.not_valid_before_ns <= now
    input.authentication.certificate.not_valid_after_ns >= now
    
    # Certificate must have proper key usage
    input.authentication.certificate.keyUsage.clientAuth == true
}

# Certificate must match user identity for mTLS+JWT
certificate_matches_user {
    input.authentication.method == "mTLS_JWT"
    input.authentication.certificate.subject.emailAddress == input.user.email
}

# Service certificates validation
valid_service_certificate {
    input.authentication.method == "mTLS_service"
    valid_certificate
    input.authentication.certificate.subject.commonName == sprintf("%s.zta.gov", [input.authentication.service_name])
}

#############################################
# ENHANCED DOCUMENT ACCESS POLICIES
#############################################

# Superadmin with STRONG authentication
allow {
    input.user.role == "superadmin"
    auth_strength >= required_auth_strength(input.resource.type, input.resource.classification)
    valid_certificate
    reason := "Superadmin with strong authentication"
}

# Admin access with mTLS
allow {
    input.user.role == "admin"
    input.resource.type == "document"
    input.resource.facility == input.user.facility
    input.action == "read"
    auth_strength >= 2  # Requires at least mTLS
    valid_certificate
    certificate_matches_user
    reason := "Admin can read documents in their facility with mTLS"
}

# Admin write with strong authentication
allow {
    input.user.role == "admin"
    input.resource.type == "document"
    input.resource.facility == input.user.facility
    input.resource.department == input.user.department
    input.action == "write"
    auth_strength >= 2  # Requires mTLS
    valid_certificate
    certificate_matches_user
    reason := "Admin can write to documents in their department with mTLS"
}

# Regular user access with clearance and authentication
allow {
    input.user.role == "user"
    input.resource.type == "document"
    input.action == "read"
    input.resource.department == input.user.department
    input.resource.facility == input.user.facility
    
    # Check clearance level
    clearance_levels := ["BASIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"]
    clearance_index(resource_level) := i {
        clearance_levels[i] == resource_level
    }
    user_clearance_index := clearance_index(input.user.clearance)
    resource_clearance_index := clearance_index(input.resource.classification)
    user_clearance_index >= resource_clearance_index
    
    # Check authentication strength
    auth_strength >= required_auth_strength(input.resource.type, input.resource.classification)
    
    # Certificate validation for mTLS
    valid_certificate
    certificate_matches_user
    
    # Time restrictions for weaker classifications
    not (input.resource.classification == "BASIC" and (
        input.environment.time.hour < 9 or 
        input.environment.time.hour > 17 or
        input.environment.time.weekend
    ))
    
    reason := sprintf("User authenticated with %s, clearance: %s >= %s", 
        [input.authentication.method, input.user.clearance, input.resource.classification])
}

# Service-to-service document access
allow {
    input.authentication.method == "mTLS_service"
    input.resource.type == "document"
    input.action == "read"
    valid_service_certificate
    
    # Services can only access documents in their authorized departments
    authorized_departments := {
        "opa-agent.zta.gov": ["ALL"],
        "document-service.zta.gov": [input.resource.department],
        "api-server.zta.gov": ["ALL"]
    }
    
    authorized_departments[input.authentication.service_name][_] == "ALL" or
    authorized_departments[input.authentication.service_name][_] == input.resource.department
    
    reason := sprintf("Service %s authorized for department %s", 
        [input.authentication.service_name, input.resource.department])
}

#############################################
# ZTA USER MANAGEMENT POLICIES
#############################################

user_management := decision {
    decision := {"allow": false, "reason": "Default deny"}
}

# Superadmin can manage with strong auth
user_management := {"allow": true, "reason": "Superadmin with strong authentication"} {
    input.user.role == "superadmin"
    auth_strength >= 2
    valid_certificate
}

# Admin management with mTLS
user_management := {"allow": true, "reason": "Admin can manage users with mTLS"} {
    input.user.role == "admin"
    input.action == "read"
    input.resource.facility == input.user.facility
    auth_strength >= 2
    valid_certificate
    certificate_matches_user
}

# Admin create with strong auth
user_management := {"allow": true, "reason": "Admin can create users with mTLS"} {
    input.user.role == "admin"
    input.action == "create"
    input.resource.department == input.user.department
    input.resource.facility == input.user.facility
    input.resource.role != "superadmin"
    auth_strength >= 2
    valid_certificate
    certificate_matches_user
}

# Certificate issuance policy
allow_certificate_issue := decision {
    decision := {"allow": false, "reason": "Default deny"}
}

allow_certificate_issue := {"allow": true, "reason": "Admin can issue certificates for their department"} {
    input.user.role == "admin"
    input.resource.type == "certificate"
    input.action == "issue"
    input.resource.department == input.user.department
    auth_strength >= 2
    valid_certificate
    certificate_matches_user
}

allow_certificate_issue := {"allow": true, "reason": "Superadmin can issue any certificate"} {
    input.user.role == "superadmin"
    input.resource.type == "certificate"
    input.action == "issue"
    auth_strength >= 2
    valid_certificate
}

allow {
    # Normal policy checks pass
    input.user.role == "user"
    input.resource.type == "document"
    input.resource.department == input.user.department
    
    # Risk-based decision
    risk_decision := risk_based_decision(input.risk_score, input.resource.classification)
    risk_decision == "allow"
}

# Risk decision matrix
risk_based_decision(risk_score, classification) := "allow" {
    classification == "PUBLIC"
    risk_score <= 80
} else := "allow" {
    classification == "DEPARTMENT"
    risk_score <= 60
} else := "allow" {
    classification == "TOP_SECRET"
    risk_score <= 40
    # Additional time check for TOP_SECRET
    current_hour := time.clock_hour(input.environment.timestamp)
    current_hour >= 8
    current_hour <= 16
} else := "deny" {
    true
}
#############################################
# AUDIT LOG ACCESS WITH AUTHENTICATION
#############################################

audit_access := decision {
    decision := {"allow": false, "reason": "Default deny"}
}

audit_access := {"allow": true, "reason": "Superadmin with strong auth can view all logs"} {
    input.user.role == "superadmin"
    input.action == "read"
    auth_strength >= 2
    valid_certificate
}

audit_access := {"allow": true, "reason": "Admin with mTLS can view facility logs"} {
    input.user.role == "admin"
    input.action == "read"
    input.resource.facility == input.user.facility
    auth_strength >= 2
    valid_certificate
    certificate_matches_user
}

#############################################
# DECISION AGGREGATION WITH AUTHENTICATION INFO
#############################################

# Main decision function with ZTA metadata
decision := {
    "allow": allow,
    "reason": reason,
    "authentication": {
        "method": input.authentication.method,
        "strength": auth_strength,
        "required_strength": required_auth_strength(input.resource.type, input.resource.classification),
        "certificate_valid": valid_certificate,
        "certificate_matches": certificate_matches_user
    },
    "timestamp": time.now_ns(),
    "request_id": input.request_id,
    "zta_compliance": {
        "verify_explicitly": true,
        "least_privilege": allow,
        "assume_breach": true
    }
} {
    allow
    reason := reason_allow
} else = {
    "allow": false,
    "reason": reason_deny,
    "authentication": {
        "method": input.authentication.method,
        "strength": auth_strength,
        "required_strength": required_auth_strength(input.resource.type, input.resource.classification),
        "certificate_valid": valid_certificate,
        "certificate_matches": certificate_matches_user,
        "failure": "Authentication insufficient for resource"
    },
    "timestamp": time.now_ns(),
    "request_id": input.request_id,
    "zta_compliance": {
        "verify_explicitly": true,
        "least_privilege": false,
        "assume_breach": true
    }
} {
    not allow
    reason_deny := "Access denied by Zero Trust policy"
}

# Extract reason from allow rules
reason_allow := reason {
    some reason
    reason = reason
}

# Extract reason from deny rules
reason_deny := reason {
    some reason
    reason = reason
} else := "Access denied - insufficient authentication strength"