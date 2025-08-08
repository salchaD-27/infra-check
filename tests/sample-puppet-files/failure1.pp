package { 'mysql-server':
  ensure => present,
  password => 'supersecret',  
}

service { 'mysql':
  ensure => running,
  enable => true,
}  

# No class declaration in this manifest, password is hardcoded,
# and there is trailing whitespace on some lines