variable "resource_group_name" {
  type = string
}

variable "location" {
  type    = string
  default = "eastus"
}

variable "cluster_name" {
  type = string
}

variable "kubernetes_version" {
  type    = string
  default = "1.30"
}

variable "node_vm_size" {
  type    = string
  default = "Standard_D2s_v3"
}

variable "min_nodes" {
  type    = number
  default = 2
}

variable "max_nodes" {
  type    = number
  default = 10
}

variable "desired_nodes" {
  type    = number
  default = 3
}

variable "redis_capacity" {
  type    = number
  default = 1
}

variable "redis_family" {
  type    = string
  default = "C"
}

variable "redis_sku" {
  type    = string
  default = "Standard"
}

variable "postgres_version" {
  type    = string
  default = "16"
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

variable "db_storage_mb" {
  type    = number
  default = 32768
}

variable "db_sku_name" {
  type    = string
  default = "B_Standard_B1ms"
}

variable "db_backup_retention_days" {
  type    = number
  default = 7
}

variable "tags" {
  type    = map(string)
  default = {}
}
