variable "project_id" {
  description = "GCP project ID"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "us-central1"
}

variable "cluster_name" {
  type = string
}

variable "kubernetes_version" {
  type    = string
  default = "1.30"
}

variable "vpc_network" {
  type    = string
  default = "default"
}

variable "vpc_subnetwork" {
  type    = string
  default = "default"
}

variable "node_machine_type" {
  type    = string
  default = "n2-standard-2"
}

variable "node_disk_gb" {
  type    = number
  default = 50
}

variable "preemptible_nodes" {
  type    = bool
  default = false
}

variable "min_nodes" {
  type    = number
  default = 2
}

variable "max_nodes" {
  type    = number
  default = 10
}

variable "redis_tier" {
  type    = string
  default = "STANDARD_HA"
}

variable "redis_memory_gb" {
  type    = number
  default = 1
}

variable "db_tier" {
  type    = string
  default = "db-g1-small"
}

variable "db_availability_type" {
  description = "REGIONAL for HA, ZONAL for single-zone"
  type        = string
  default     = "REGIONAL"
}

variable "db_backup_retention_days" {
  type    = number
  default = 7
}

variable "db_deletion_protection" {
  type    = bool
  default = true
}

variable "db_username" {
  type      = string
  sensitive = true
  default   = "haltchain"
}

variable "db_password" {
  type      = string
  sensitive = true
}

variable "labels" {
  type    = map(string)
  default = {}
}
