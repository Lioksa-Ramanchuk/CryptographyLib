namespace CryptographyLib;

public abstract class Hasher<T1, T2> : IHasher<T1, T2>, IFileHasher
{
    public abstract T2 Hash(T1 text);
    public void HashFile(string pathText, string pathHashed)
    {
        using var tempSrcCopy = new TempFileCopy(pathText);
        File.Create(pathHashed).Dispose();
        ProcessFile(tempSrcCopy.Name, pathHashed);
    }

    protected abstract void ProcessFile(string pathFrom, string pathTo);

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