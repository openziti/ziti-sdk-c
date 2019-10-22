pipeline {
  agent { docker { image 'netfoundry/ziti-build-pipeline:latest'}}
  stages {
    stage('Build') {
      steps {
        sh 'git submodule update --init --recursive'
        sh 'git submodule status --recursive'
        sh 'ls -R deps'
        sh 'echo "Running tests"'
        sh 'mkdir build-test && (cd build-test && cmake .. && cmake --build . --target all_tests && ctest -VV)'
      }
    }
  }
}