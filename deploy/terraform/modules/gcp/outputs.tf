output "cluster_name" {
  value = google_container_cluster.haltchain.name
}

output "cluster_endpoint" {
  value     = google_container_cluster.haltchain.endpoint
  sensitive = true
}

output "cluster_ca_certificate" {
  value     = google_container_cluster.haltchain.master_auth[0].cluster_ca_certificate
  sensitive = true
}

output "redis_host" {
  value = google_redis_instance.haltchain.host
}

output "redis_auth_string" {
  value     = google_redis_instance.haltchain.auth_string
  sensitive = true
}

output "database_connection_name" {
  value = google_sql_database_instance.haltchain.connection_name
}

output "database_private_ip" {
  value = google_sql_database_instance.haltchain.private_ip_address
}
