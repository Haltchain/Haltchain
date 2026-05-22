output "cluster_name" {
  value = azurerm_kubernetes_cluster.haltchain.name
}

output "kube_config" {
  value     = azurerm_kubernetes_cluster.haltchain.kube_config_raw
  sensitive = true
}

output "redis_hostname" {
  value = azurerm_redis_cache.haltchain.hostname
}

output "redis_primary_access_key" {
  value     = azurerm_redis_cache.haltchain.primary_access_key
  sensitive = true
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.haltchain.fqdn
}
