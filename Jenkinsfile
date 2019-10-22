pipeline {
  agent any
  stages {
    stage('Build') {
      steps {
        sh '''git submodule update --init --recursive
echo "Running tests"'''
      }
    }
  }
}