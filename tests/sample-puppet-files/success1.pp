# Has a class declaration.
# Uses valid resource types (package, service, file).
# No hardcoded passwords or secrets.
# No trailing whitespace.
# No deprecated or disallowed parameters.

class webserver {
  package { 'nginx':
    ensure => installed,
  }

  service { 'nginx':
    ensure => running,
    enable => true,
  }

  file { '/etc/nginx/nginx.conf':
    ensure  => file,
    content => template('nginx/nginx.conf.erb'),
  }
}