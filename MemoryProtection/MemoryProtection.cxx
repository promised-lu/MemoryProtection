#include <windows.h>

HANDLE g_hProcessHeap;
HANDLE g_hIsolatedHeap;

namespace MemoryProtection
{
	class SBlockDescriptor
	{
	public:
		void SetDescriptorData(ULONG_PTR Block, SIZE_T Size, bool UsingIsoHeap)
		{
			m_Block = Block;
			m_Size = Size;
			if (UsingIsoHeap)
				m_Block = Block | 2;
		}

		ULONG_PTR BaseAddress()
		{
			return m_Block & ~3;
		}

		bool IsMarked()
		{
			return m_Block & 1;
		}

		void Mark()
		{
			m_Block |= 1;
		}

		void Unmark()
		{
			m_Block &= ~1;
		}

		bool IsBlockUsingIsoHeap()
		{
			return m_Block & 2;
		}

		static int __cdecl BaseAddressCompare(void *Context, SBlockDescriptor *BlockDescriptor1, SBlockDescriptor *BlockDescriptor2)
		{
			if (BlockDescriptor1->BaseAddress() > BlockDescriptor2->BaseAddress())
			{
				return 1;
			}
			else if (BlockDescriptor1->BaseAddress() < BlockDescriptor2->BaseAddress())
			{
				return -1;
			}
			else
			{
				return 0;
			}
		}

		static int __cdecl AddressInBlockRange(void *Context, ULONG_PTR Block, SBlockDescriptor *BlockDescriptor)
		{
			if (Block >= BlockDescriptor->BaseAddress())
			{
				if (Block < BlockDescriptor->HighAddress())
				{
					return 0;
				}
				else
				{
					return 1;
				}
			}
			else
			{
				return -1;
			}
		}

		ULONG_PTR HighAddress()
		{
			return BaseAddress() + m_Size;
		}

		ULONG_PTR GetBlock() const
		{
			return m_Block;
		}

		void SetBlock(ULONG_PTR Block)
		{
			m_Block = Block;
		}

		SIZE_T GetSize() const
		{
			return m_Size;
		}

		void SetSize(SIZE_T Size)
		{
			m_Size = Size;
		}
	private:
		ULONG_PTR m_Block;
		SIZE_T m_Size;
	};

	class SBlockDescriptorArray
	{
	public:
		SBlockDescriptorArray() : m_BlockDescriptors(NULL), m_Size(0), m_Count(0), m_MaxCount(0), m_Sorted(false)
		{
		}

		bool EnsureFreeSlot()
		{
			SBlockDescriptor *BlockDescriptors = m_BlockDescriptors;
			ULONG MaxCount = m_MaxCount;

			if (BlockDescriptors)
			{
				if (m_Count == MaxCount)
				{
					MaxCount *= 2;
					BlockDescriptors = (SBlockDescriptor *)HeapReAlloc(g_hProcessHeap, 0, BlockDescriptors, sizeof(BlockDescriptors[0]) * MaxCount);
				}
			}
			else
			{
				MaxCount = 1024;
				BlockDescriptors = (SBlockDescriptor *)HeapAlloc(g_hProcessHeap, 0, sizeof(BlockDescriptors[0]) * MaxCount);
			}

			if (BlockDescriptors)
			{
				m_BlockDescriptors = BlockDescriptors;
				m_MaxCount = MaxCount;
				return true;
			}
			else
			{
				return false;
			}
		}

		bool AddBlockDescriptor(ULONG_PTR Block, bool UsingIsoHeap, SIZE_T *pSize)
		{
			*pSize = 0;

			if (EnsureFreeSlot())
			{
				HANDLE hHeap = g_hIsolatedHeap;
				if (!UsingIsoHeap)
					hHeap = g_hProcessHeap;

				*pSize = HeapSize(hHeap, 0, (LPCVOID)Block);
				m_Size += *pSize;

				m_BlockDescriptors[m_Count++].SetDescriptorData(Block, *pSize, UsingIsoHeap);

				m_Sorted = false;
				return true;
			}

			return false;
		}

		void RemoveBlockDescriptorAt(ULONG i)
		{
			m_Count--;
			m_Size -= m_BlockDescriptors[i].GetSize();

			m_BlockDescriptors[i].SetBlock(m_BlockDescriptors[m_Count].GetBlock());
			m_BlockDescriptors[i].SetSize(m_BlockDescriptors[m_Count].GetSize());

			m_Sorted = false;
		}

		void HeapFreeAllBlocks()
		{
			for (ULONG i = 0; i < m_Count; i++)
			{
				SBlockDescriptor *BlockDescriptor = &m_BlockDescriptors[i];

				HANDLE hHeap = g_hIsolatedHeap;
				if (!BlockDescriptor->IsBlockUsingIsoHeap())
					hHeap = g_hProcessHeap;

				::HeapFree(hHeap, 0, (LPVOID)BlockDescriptor->BaseAddress());
			}

			m_Size = 0;
			m_Count = 0;
		}

		void EnsureBlocksAreSorted()
		{
			if (!m_Sorted)
			{
				if (m_Count)
				{
					qsort_s(m_BlockDescriptors, m_Count, sizeof(m_BlockDescriptors[0]), (int(_cdecl *)(void *, const void *, const void *))SBlockDescriptor::BaseAddressCompare, NULL);
					m_Sorted = true;
				}
			}
		}

		SBlockDescriptor *GetBlockDescriptorAt(ULONG i)
		{
			return &m_BlockDescriptors[i];
		}

		SBlockDescriptor *FindBlockDescriptorByAddressInRange(ULONG_PTR Block)
		{
			if (m_Count)
			{
				EnsureBlocksAreSorted();
				return (SBlockDescriptor *)bsearch_s((const void *)Block, m_BlockDescriptors, m_Count, sizeof(m_BlockDescriptors[0]), (int(_cdecl *)(void *, const void *, const void *))SBlockDescriptor::AddressInBlockRange, NULL);
			}
			else
			{
				return (SBlockDescriptor *)NULL;
			}
		}

		ULONG_PTR LowAddress()
		{
			if (m_Count)
			{
				EnsureBlocksAreSorted();
				return m_BlockDescriptors[0].BaseAddress();
			}
			else
			{
				return 0;
			}
		}

		ULONG_PTR HighAddress()
		{
			if (m_Count)
			{
				EnsureBlocksAreSorted();
				return m_BlockDescriptors[m_Count - 1].HighAddress();
			}
			else
			{
				return 0;
			}
		}

		SIZE_T GetSize() const
		{
			return m_Size;
		}

		ULONG GetCount() const
		{
			return m_Count;
		}
	private:
		SBlockDescriptor *m_BlockDescriptors;
		SIZE_T m_Size;
		ULONG m_Count;
		ULONG m_MaxCount;
		bool m_Sorted;
	};

	class CMemoryProtector : public SBlockDescriptorArray
	{
	public:
		CMemoryProtector() : m_ForceReclaim(false), m_StackHighAddress(0), m_StackFrame(0)
		{
		}

		static CMemoryProtector *Instance()
		{
			if (tlsSlotForInstance != TLS_OUT_OF_INDEXES)
				return (CMemoryProtector *)TlsGetValue(tlsSlotForInstance);

			return (CMemoryProtector *)NULL;
		}

		static bool ProtectProcess()
		{
			tlsSlotForInstance = TlsAlloc();
			return tlsSlotForInstance != TLS_OUT_OF_INDEXES;
		}

		void ReclaimMemoryWithoutProtection()
		{
			if (GetCount())
			{
				HeapFreeAllBlocks();
			}
		}

		void MarkBlockForAddress(ULONG_PTR Block, ULONG_PTR Low, ULONG_PTR High)
		{
			if (Block >= Low && Block < High)
			{
				SBlockDescriptor *BlockDescriptor = FindBlockDescriptorByAddressInRange(Block);

				if (BlockDescriptor)
				{
					if (!BlockDescriptor->IsMarked())
						BlockDescriptor->Mark();
				}
			}
		}

		bool CaptureStackHighAddress()
		{
			volatile ULONG_PTR StackFrame;
			MEMORY_BASIC_INFORMATION Buffer;

			if (VirtualQuery((LPCVOID)&StackFrame, &Buffer, sizeof(Buffer)) == sizeof(Buffer))
			{
				m_StackHighAddress = (ULONG_PTR)Buffer.BaseAddress + Buffer.RegionSize;
				return true;
			}

			return false;
		}

		void MarkBlocks(ULONG_PTR *Blocks)
		{
			ULONG_PTR Low = LowAddress();
			ULONG_PTR High = HighAddress();

			for (ULONG i = (m_StackHighAddress - (ULONG_PTR)Blocks) / sizeof(ULONG_PTR); i != 0; i--)
			{
				MarkBlockForAddress(*Blocks++, Low, High);
			}
		}

		void ReclaimUnmarkedBlocks()
		{
			for (ULONG i = 0; i < GetCount(); i++)
			{
				SBlockDescriptor *BlockDescriptor = GetBlockDescriptorAt(i);

				if (BlockDescriptor->IsMarked())
				{
					BlockDescriptor->Unmark();
				}
				else
				{
					HANDLE hHeap = g_hIsolatedHeap;
					if (!BlockDescriptor->IsBlockUsingIsoHeap())
					{
						hHeap = g_hProcessHeap;
					}

					::HeapFree(hHeap, 0, (LPVOID)BlockDescriptor->BaseAddress());

					RemoveBlockDescriptorAt(i--);
				}
			}
		}

		static void ProtectCurrentThread()
		{
			volatile DWORD Flag;

			if (tlsSlotForInstance != TLS_OUT_OF_INDEXES)
			{
				CMemoryProtector *MemoryProtector = (CMemoryProtector *)TlsGetValue(tlsSlotForInstance);

				if (MemoryProtector)
				{
					if (MemoryProtector->m_StackFrame <= (ULONG_PTR)&Flag)
					{
						MemoryProtector->m_StackFrame = (ULONG_PTR)&Flag;

						MemoryProtector->ReclaimMemoryWithoutProtection();
					}
				}
				else
				{
					//if (CoInternetFeatureValueInternal(&g_IndexFEATURE_MEMPROTECT_MODE, &Flag))
					{
						Flag = 1;
					}

					if (Flag)
					{
						CMemoryProtector *MemoryProtector = new CMemoryProtector();

						if (MemoryProtector == NULL || !TlsSetValue(tlsSlotForInstance, MemoryProtector) || !MemoryProtector->CaptureStackHighAddress())
						{
							DebugBreak();
						}

						if (Flag == 2)
						{
							MemoryProtector->m_ForceReclaim = true;
						}
					}
				}
			}
		}

		void ReclaimMemory(ULONG_PTR *Blocks, UINT Size)
		{
			if (GetCount() && (GetSize() >= Size || m_ForceReclaim))
			{
				MarkBlocks(Blocks);
				ReclaimUnmarkedBlocks();
			}
		}

		static void UnprotectCurrentThread()
		{
			if (tlsSlotForInstance != TLS_OUT_OF_INDEXES)
			{
				CMemoryProtector *MemoryProtector = (CMemoryProtector *)TlsGetValue(tlsSlotForInstance);

				TlsSetValue(tlsSlotForInstance, NULL);

				if (MemoryProtector)
				{
					MemoryProtector->HeapFreeAllBlocks();
					delete MemoryProtector;
				}
			}
		}

		static void __stdcall ProtectedFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
		{
			if (lpMem)
			{
				CMemoryProtector *MemoryProtector = Instance();

				if (MemoryProtector)
				{
					MemoryProtector->ReclaimMemory((ULONG_PTR *)&lpMem, 100000);

					SIZE_T Size = 0;

					if (MemoryProtector->AddBlockDescriptor((ULONG_PTR)lpMem, hHeap == g_hIsolatedHeap, &Size))
					{
						memset(lpMem, 0, Size);
					}
					else
					{
						DebugBreak();
					}
				}
				else
				{
					::HeapFree(hHeap, dwFlags, lpMem);
				}
			}
		}

		static void __stdcall UnprotectProcess(LPVOID lpvReserved)
		{
			if (lpvReserved != NULL && tlsSlotForInstance != TLS_OUT_OF_INDEXES)
			{
				UnprotectCurrentThread();

				TlsFree(tlsSlotForInstance);
				tlsSlotForInstance = TLS_OUT_OF_INDEXES;
			}
		}
	private:
		static DWORD tlsSlotForInstance;
		bool m_ForceReclaim;
		ULONG_PTR m_StackHighAddress;
		ULONG_PTR m_StackFrame;
	};

	DWORD CMemoryProtector::tlsSlotForInstance = TLS_OUT_OF_INDEXES;

	BOOL __stdcall DllNotification(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
	{
		switch (fdwReason)
		{
		case DLL_PROCESS_ATTACH:
			CMemoryProtector::ProtectProcess();
			break;
		case DLL_THREAD_ATTACH:
			CMemoryProtector::ProtectCurrentThread();
			break;
		case DLL_THREAD_DETACH:
			CMemoryProtector::UnprotectCurrentThread();
			break;
		case DLL_PROCESS_DETACH:
			CMemoryProtector::UnprotectProcess(lpvReserved);
			break;
		}
		return TRUE;
	}

	BOOL __stdcall HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem)
	{
		CMemoryProtector::ProtectedFree(hHeap, dwFlags, lpMem);
		return TRUE;
	}
}

BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		g_hProcessHeap = GetProcessHeap();
		g_hIsolatedHeap = HeapCreate(0, 0, 0);
		if (g_hIsolatedHeap)
		{
			ULONG HeapInformation = 2;
			HeapSetInformation(g_hProcessHeap, HeapCompatibilityInformation, &HeapInformation, sizeof(HeapInformation));
			HeapSetInformation(g_hIsolatedHeap, HeapCompatibilityInformation, &HeapInformation, sizeof(HeapInformation));
		}
		else
		{
			return FALSE;
		}
		MemoryProtection::DllNotification(hinstDLL, fdwReason, lpvReserved);
		break;
	case DLL_THREAD_ATTACH:
		MemoryProtection::DllNotification(hinstDLL, fdwReason, lpvReserved);
		break;
	case DLL_THREAD_DETACH:
		MemoryProtection::DllNotification(hinstDLL, fdwReason, lpvReserved);
		break;
	case DLL_PROCESS_DETACH:
		MemoryProtection::DllNotification(hinstDLL, fdwReason, lpvReserved);
		if (lpvReserved == NULL && g_hIsolatedHeap)
		{
			HeapDestroy(g_hIsolatedHeap);
			g_hIsolatedHeap = NULL;
		}
		break;
	}
	return TRUE;
}