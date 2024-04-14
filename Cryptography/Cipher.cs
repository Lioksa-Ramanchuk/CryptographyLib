namespace Cryptography;

public abstract class Cipher<T> : ICodec<T>, IFileCodec
{
    protected enum ProcessMethod
    {
        Encrypt = 1,
        Decrypt = -1,
    }

    public abstract T Encrypt(T text);
    public abstract T Decrypt(T encrypted);

    public void EncryptFile(string pathText, string pathEncrypted)
    {
        using var tempSrcCopy = new TempFileCopy(pathText);
        ProcessFile(tempSrcCopy.Name, pathEncrypted, ProcessMethod.Encrypt);
    }
    public void DecryptFile(string pathEncrypted, string pathText)
    {
        using var tempSrcCopy = new TempFileCopy(pathEncrypted);
        ProcessFile(tempSrcCopy.Name, pathText, ProcessMethod.Decrypt);
    }

    protected abstract void ProcessFile(string pathFrom, string pathTo, ProcessMethod processMethod);

    private class TempFileCopy : IDisposable
    {
        private bool _disposedValue;

        public TempFileCopy(string src)
        {
            Source = src;
            Name = Path.GetRandomFileName();
            File.Copy(src, Name);
        }

        public string Source { get; private set; }

        public string Name { get; private set; }

        public void Dispose()
        {
            Dispose(disposing: true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposedValue)
            {
                if (disposing)
                {
                    File.Delete(Name);
                }

                _disposedValue = true;
            }
        }
    }
}