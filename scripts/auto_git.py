from subprocess import run,Popen,PIPE
import os,sys,path,time

def main():
  print(__name__ +': Started...')
  while(True):
    try:
      run('git pull'.split())
      run('git add .'.split())
      run('git commit -m "auto_git_runner"'.split())
      run('git push')
      time.sleep(60)
    except Exception as e:
        print('ERROR', e)
        print('Exiting loop...')
        break
    print(__name__ + ':Finished')
if __name__ == '__main__':
  main()
  
