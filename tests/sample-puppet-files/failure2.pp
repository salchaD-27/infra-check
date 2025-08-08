# Uses deprecated resource type execpipe.
# Uses a disallowed/unmanaged parameter unmanaged_param.
# Missing class declaration.

execpipe { 'run_script':
  command => '/usr/local/bin/deploy.sh',
  timeout => 600,
  unmanaged_param => 'some value',
}