namespace Native.Memory
{
    using System;
    using System.Runtime.InteropServices;
    using System.Text;

    public class MemoryAlloc : IDisposable
    {
        public MemoryAlloc()
        {
        }

        public MemoryAlloc(int size)
        {
            Pointer = Marshal.AllocHGlobal(size);
            Size = size;
        }

        public MemoryAlloc(IntPtr ptr) : this(ptr, 0)
        {
        }

        public MemoryAlloc(IntPtr ptr, int size)
        {
            Pointer = ptr;
            Size = size;
        }

        public void Dispose()
        {
            Free();
        }

        public void Free()
        {
            if (Pointer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(Pointer);
            }
        }

        public void IncrementSize(int newBytesCount)
        {
            IntPtr cb = new(newBytesCount + Size);
            Pointer = Marshal.ReAllocHGlobal(Pointer, cb);
            Size = newBytesCount + Size;
        }

        public static implicit operator int(MemoryAlloc memory)
        {
            return memory.Pointer.ToInt32();
        }

        public static implicit operator long(MemoryAlloc memory)
        {
            return memory.Pointer.ToInt64();
        }

        public static implicit operator IntPtr(MemoryAlloc memory)
        {
            return memory.Pointer;
        }

        public int ReadByte(int offset)
        {
            return ReadByte(offset, 0);
        }

        public int ReadByte(int offset, int index)
        {
            return Marshal.ReadByte(Pointer, offset + (index * 4));
        }

        public byte[] ReadBytes(int length)
        {
            return ReadBytes(0, length);
        }

        public byte[] ReadBytes(int offset, int length)
        {
            byte[] buffer = new byte[length - 1 + 1];
            ReadBytes(offset, buffer, 0, length);
            return buffer;
        }

        public void ReadBytes(byte[] buffer, int startIndex, int length)
        {
            ReadBytes(0, buffer, startIndex, length);
        }

        public void ReadBytes(int offset, byte[] buffer, int startIndex, int length)
        {
            Pointer = new IntPtr(Pointer.ToInt64() + offset);
            Marshal.Copy(Pointer, buffer, startIndex, length);
        }

        public int ReadInt32(int offset)
        {
            return ReadInt32(offset, 0);
        }

        public int ReadInt32(int offset, int index)
        {
            return Marshal.ReadInt32(Pointer, offset + (index * 4));
        }

        public IntPtr ReadIntPtr(int offset)
        {
            return ReadIntPtr(offset, 0);
        }

        public IntPtr ReadIntPtr(int offset, int index)
        {
            return Marshal.ReadIntPtr(Pointer, offset + (index * IntPtr.Size));
        }

        public T ReadStruct<T>()
        {
            return ReadStruct<T>(0);
        }

        public T ReadStruct<T>(int index)
        {
            return ReadStruct<T>(0, index);
        }

        public T ReadStruct<T>(int offset, int index)
        {
            Pointer = new IntPtr(offset + (Marshal.SizeOf(typeof(T)) * index) + Pointer.ToInt64());
            return (T)Marshal.PtrToStructure(Pointer, typeof(T));
        }

        public T ReadStructOffset<T>(int offset)
        {
            Pointer = new IntPtr(Pointer.ToInt64() + offset);
            return (T)Marshal.PtrToStructure(Pointer, typeof(T));
        }

        public uint ReadUInt32(int offset)
        {
            return ReadUInt32(offset, 0);
        }

        public uint ReadUInt32(int offset, int index)
        {
            return (uint)ReadInt32(offset, index);
        }

        public void Resize(int newSize)
        {
            IntPtr cb = new(newSize);
            Pointer = Marshal.ReAllocHGlobal(Pointer, cb);
            Size = newSize;
        }

        public void WriteByte(int offset, byte b)
        {
            Marshal.WriteByte(this, offset, b);
        }

        public void WriteBytes(int offset, byte[] b)
        {
            Pointer = new IntPtr(Pointer.ToInt64() + offset);
            Marshal.Copy(b, 0, Pointer, b.Length);
        }

        public void WriteInt16(int offset, short i)
        {
            Marshal.WriteInt16(this, offset, i);
        }

        public void WriteInt32(int offset, int i)
        {
            Marshal.WriteInt32(this, offset, i);
        }

        public void WriteIntPtr(int offset, IntPtr i)
        {
            Marshal.WriteIntPtr(this, offset, i);
        }

        public void WriteStruct<T>(T s)
        {
            WriteStruct(0, s);
        }

        public void WriteStruct<T>(int index, T s)
        {
            WriteStruct(0, index, s);
        }

        public void WriteStruct<T>(int offset, int index, T s)
        {
            Pointer = new IntPtr(Pointer.ToInt64() + offset + (Marshal.SizeOf(typeof(T)) * index));
            Marshal.StructureToPtr(s, Pointer, false);
        }

        public void WriteUnicodeString(int offset, string s)
        {
            byte[] bytes = Encoding.Unicode.GetBytes(s);
            int num = bytes.Length - 1;
            for (int i = 0; i <= num; i++)
            {
                Marshal.WriteByte(Pointer, offset + i, bytes[i]);
            }
        }

        public IntPtr Pointer { get; set; }

        public int Size { get; set; }
    }
}

