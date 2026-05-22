terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

###############################################################################
# GKE Cluster
###############################################################################

resource "google_container_cluster" "haltchain" {
  name     = var.cluster_name
  location = var.region
  project  = var.project_id

  # We define our own node pool below; remove the default one.
  remove_default_node_pool = true
  initial_node_count       = 1

  min_master_version = var.kubernetes_version
  network            = var.vpc_network
  subnetwork         = var.vpc_subnetwork

  workload_identity_config {
    workload_pool = "${var.project_id}.svc.id.goog"
  }

  resource_labels = var.labels
}

resource "google_container_node_pool" "haltchain" {
  name       = "${var.cluster_name}-pool"
  location   = var.region
  cluster    = google_container_cluster.haltchain.name
  project    = var.project_id

  autoscaling {
    min_node_count = var.min_nodes
    max_node_count = var.max_nodes
  }

  node_config {
    preemptible  = var.preemptible_nodes
    machine_type = var.node_machine_type
    disk_size_gb = var.node_disk_gb

    oauth_scopes = [
      "https://www.googleapis.com/auth/cloud-platform",
    ]

    labels = merge(var.labels, {
      "haltchain.io/node-pool" = "default"
    })

    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
  }
}

###############################################################################
# Cloud Memorystore (Redis)
###############################################################################

resource "google_redis_instance" "haltchain" {
  name           = "${var.cluster_name}-redis"
  tier           = var.redis_tier
  memory_size_gb = var.redis_memory_gb
  region         = var.region
  project        = var.project_id

  redis_version          = "REDIS_7_0"
  transit_encryption_mode = "SERVER_AUTHENTICATION"
  auth_enabled           = true

  labels = var.labels
}

###############################################################################
# Cloud SQL (PostgreSQL)
###############################################################################

resource "google_sql_database_instance" "haltchain" {
  name             = "${var.cluster_name}-postgres"
  database_version = "POSTGRES_16"
  region           = var.region
  project          = var.project_id

  deletion_protection = var.db_deletion_protection

  settings {
    tier              = var.db_tier
    availability_type = var.db_availability_type

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      backup_retention_settings {
        retained_backups = var.db_backup_retention_days
      }
    }

    ip_configuration {
      ipv4_enabled    = false
      require_ssl     = true
      private_network = "projects/${var.project_id}/global/networks/${var.vpc_network}"
    }

    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }

    database_flags {
      name  = "log_connections"
      value = "on"
    }
  }
}

resource "google_sql_database" "haltchain" {
  name     = "haltchain"
  instance = google_sql_database_instance.haltchain.name
  project  = var.project_id
}

resource "google_sql_user" "haltchain" {
  name     = var.db_username
  instance = google_sql_database_instance.haltchain.name
  password = var.db_password
  project  = var.project_id
}
