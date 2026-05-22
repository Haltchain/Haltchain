terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

###############################################################################
# Resource Group
###############################################################################

resource "azurerm_resource_group" "haltchain" {
  name     = var.resource_group_name
  location = var.location
  tags     = var.tags
}

###############################################################################
# AKS
###############################################################################

resource "azurerm_kubernetes_cluster" "haltchain" {
  name                = var.cluster_name
  location            = azurerm_resource_group.haltchain.location
  resource_group_name = azurerm_resource_group.haltchain.name
  dns_prefix          = var.cluster_name
  kubernetes_version  = var.kubernetes_version

  default_node_pool {
    name       = "system"
    node_count = var.desired_nodes
    vm_size    = var.node_vm_size

    min_count  = var.min_nodes
    max_count  = var.max_nodes
    enable_auto_scaling = true

    node_labels = {
      "haltchain.io/node-pool" = "default"
    }
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
    load_balancer_sku = "standard"
  }

  tags = var.tags
}

###############################################################################
# Redis Cache
###############################################################################

resource "azurerm_redis_cache" "haltchain" {
  name                = "${var.cluster_name}-redis"
  location            = azurerm_resource_group.haltchain.location
  resource_group_name = azurerm_resource_group.haltchain.name
  capacity            = var.redis_capacity
  family              = var.redis_family
  sku_name            = var.redis_sku

  enable_non_ssl_port = false
  minimum_tls_version = "1.2"

  redis_configuration {
    enable_authentication = true
  }

  tags = var.tags
}

###############################################################################
# PostgreSQL Flexible Server
###############################################################################

resource "azurerm_postgresql_flexible_server" "haltchain" {
  name                   = "${var.cluster_name}-postgres"
  resource_group_name    = azurerm_resource_group.haltchain.name
  location               = azurerm_resource_group.haltchain.location
  version                = var.postgres_version
  administrator_login    = var.db_username
  administrator_password = var.db_password
  storage_mb             = var.db_storage_mb
  sku_name               = var.db_sku_name
  backup_retention_days  = var.db_backup_retention_days

  tags = var.tags
}

resource "azurerm_postgresql_flexible_server_database" "haltchain" {
  name      = "haltchain"
  server_id = azurerm_postgresql_flexible_server.haltchain.id
  collation = "en_US.utf8"
  charset   = "utf8"
}
