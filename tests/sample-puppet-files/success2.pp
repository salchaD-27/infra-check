# Proper class declaration.
# Uses common resource types.
# No hardcoded secrets.
# No syntax issues.

class database {
  exec { 'create-database':
    command => 'createdb my_db',
    unless  => 'psql -lqt | cut -d \| -f 1 | grep -w my_db',
  }

  user { 'dbuser':
    ensure     => present,
    managehome => true,
  }
}