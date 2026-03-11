# Zero Trust Architecture for Government Document Classification System

## Thesis Project - [BRAC university]

### 📋 Overview
A Zero Trust Architecture (ZTA) implementation for secure government document classification and access control system. This project demonstrates modern security principles for sensitive government document management.

###  Key Security Features Implemented

#### Phase 1: Authentication & Identity
- JWT-based authentication with role-based claims
- Government email domain validation (@mod.gov, @mof.gov, @nsa.gov)
- Clearance level hierarchy (BASIC → TOP_SECRET)
- Department and facility-based isolation
- Password hashing with bcrypt

####  Phase 2: Policy Engine (OPA Integration)
- Open Policy Agent (OPA) for fine-grained access control
- Rego policy language for security rules
- Real-time policy evaluation for each request
- Comprehensive audit logging with decision reasons

####  Phase 3: In Progress
- Mutual TLS (mTLS) for service-to-service communication
- Certificate-based authentication
- Enhanced audit trail with certificate verification

###  Architecture