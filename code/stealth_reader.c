// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/highmem.h>
#include <linux/proc_fs.h>
#include <linux/random.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/kthread.h>
#include <linux/version.h>
#include <linux/platform_device.h>
#include <linux/of_device.h>
#include <linux/of_address.h>
#include <linux/io.h>
#include <linux/pm_runtime.h>
#include <linux/signal.h>
#include <linux/pid.h>

#define MODULE_NAME "gki_mem_reader"
#define SHARED_MEM_SIZE (2 * 1024 * 1024) // 2MB共享内存
#define SIGNAL_NUM 44 // 自定义信号号 (SIGRTMIN+10)
#define MAX_DMA_SIZE (1 * 1024 * 1024) // 最大DMA传输1MB

MODULE_LICENSE("GPL");
MODULE_AUTHOR("DeepSeek AI");
MODULE_DESCRIPTION("Stealth Hardware Memory Reader for Gen2+ SoCs");
MODULE_VERSION("3.0");

// 共享内存控制结构
struct shared_mem_control {
    atomic_t ready_flag;
    atomic_t request_flag;
    pid_t client_pid;
    phys_addr_t target_addr;
    size_t data_size;
    size_t data_offset;
    uint32_t crc32; // 数据校验
};

// SoC特定硬件配置
struct soc_hw_config {
    phys_addr_t dma_controller_base;
    u32 dma_channel_id;
    u32 max_transfer_size;
};

// 模块全局状态
struct stealth_reader {
    void *shared_virt_addr;
    phys_addr_t shared_phys_addr;
    struct shared_mem_control *ctrl;
    void *data_area;
    struct task_struct *signal_thread;
    atomic_t active;
    struct proc_dir_entry *proc_entry;
    struct device *dev;
    struct dma_chan *dma_chan;
    struct soc_hw_config hw_config;
};

static struct stealth_reader *reader_ctx;

// 简单的CRC32计算
static uint32_t calculate_crc32(const void *data, size_t len) {
    uint32_t crc = ~0U;
    const uint8_t *buf = (const uint8_t *)data;
    
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int j = 0; j < 8; j++) {
            crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
        }
    }
    
    return ~crc;
}

// Gen2+ SoC DMA初始化函数
static int init_gen2_dma(struct stealth_reader *ctx)
{
    struct device_node *np;
    struct resource res;
    int ret;
    
    // 查找DMA控制器节点
    np = of_find_compatible_node(NULL, NULL, "qcom,gen2-dma");
    if (!np) {
        np = of_find_compatible_node(NULL, NULL, "samsung,gen2-dma");
        if (!np) {
            pr_err("Failed to find Gen2+ DMA controller\n");
            return -ENODEV;
        }
    }
    
    // 获取DMA控制器物理地址
    ret = of_address_to_resource(np, 0, &res);
    if (ret) {
        pr_err("Failed to get DMA controller address\n");
        return ret;
    }
    ctx->hw_config.dma_controller_base = res.start;
    
    // 获取DMA通道ID (默认为0)
    if (of_property_read_u32(np, "dma-channel", &ctx->hw_config.dma_channel_id)) {
        ctx->hw_config.dma_channel_id = 0;
    }
    
    // 获取最大传输大小
    if (of_property_read_u32(np, "max-transfer-size", &ctx->hw_config.max_transfer_size)) {
        ctx->hw_config.max_transfer_size = MAX_DMA_SIZE;
    } else if (ctx->hw_config.max_transfer_size > MAX_DMA_SIZE) {
        ctx->hw_config.max_transfer_size = MAX_DMA_SIZE;
    }
    
    // 请求DMA通道
    dma_cap_mask_t mask;
    dma_cap_zero(mask);
    dma_cap_set(DMA_MEMCPY, mask);
    
    ctx->dma_chan = dma_request_channel(mask, NULL, NULL);
    if (!ctx->dma_chan) {
        pr_err("Failed to request DMA channel\n");
        return -ENODEV;
    }
    
    pr_info("Gen2+ DMA initialized: base=0x%llx, channel=%d, max_size=0x%x\n",
           (u64)ctx->hw_config.dma_controller_base,
           ctx->hw_config.dma_channel_id,
           ctx->hw_config.max_transfer_size);
    
    return 0;
}

// 信号处理函数
static void signal_handler(int sig, struct siginfo *info, void *context)
{
    struct stealth_reader *ctx = reader_ctx;
    
    if (!ctx || !atomic_read(&ctx->active)) 
        return;
    
    // 验证发送者PID
    if (ctx->ctrl->client_pid != info->si_pid) {
        pr_warn("Unauthorized signal from PID: %d\n", info->si_pid);
        return;
    }
    
    // 设置请求标志
    atomic_set(&ctx->ctrl->request_flag, 1);
}

// DMA内存读取函数
static int dma_read_memory(struct stealth_reader *ctx, phys_addr_t phys_addr, 
                          void *buffer, size_t size)
{
    struct dma_async_tx_descriptor *desc;
    struct scatterlist sg;
    dma_addr_t dma_handle;
    void *dma_buffer;
    enum dma_status status;
    
    // 分配DMA缓冲区
    dma_buffer = dma_alloc_coherent(ctx->dev, size, &dma_handle, GFP_KERNEL);
    if (!dma_buffer) {
        pr_warn("Failed to allocate DMA buffer\n");
        return -ENOMEM;
    }
    
    // 设置随机延迟
    unsigned int delay = get_random_u32() % 50;
    udelay(delay);
    
    // 准备scatterlist
    sg_init_table(&sg, 1);
    sg_set_page(&sg, pfn_to_page(PFN_DOWN(phys_addr)), 
               size, offset_in_page(phys_addr));
    
    // 映射DMA
    if (dma_map_sg(ctx->dev, &sg, 1, DMA_DEV_TO_MEM) == 0) {
        pr_warn("Failed to map DMA SG\n");
        dma_free_coherent(ctx->dev, size, dma_buffer, dma_handle);
        return -EIO;
    }
    
    // 准备DMA描述符
    desc = dmaengine_prep_slave_sg(ctx->dma_chan, &sg, 1, 
                                 DMA_DEV_TO_MEM, DMA_PREP_INTERRUPT);
    if (!desc) {
        pr_warn("Failed to prepare DMA descriptor\n");
        dma_unmap_sg(ctx->dev, &sg, 1, DMA_DEV_TO_MEM);
        dma_free_coherent(ctx->dev, size, dma_buffer, dma_handle);
        return -EIO;
    }
    
    // 提交DMA传输
    desc->callback = NULL;
    dmaengine_submit(desc);
    dma_async_issue_pending(ctx->dma_chan);
    
    // 等待传输完成
    status = dma_wait_for_async_tx(desc, msecs_to_jiffies(100));
    if (status != DMA_COMPLETE) {
        pr_warn("DMA transfer failed with status %d\n", status);
        dma_unmap_sg(ctx->dev, &sg, 1, DMA_DEV_TO_MEM);
        dma_free_coherent(ctx->dev, size, dma_buffer, dma_handle);
        return -EIO;
    }
    
    // 复制数据到目标缓冲区
    memcpy(buffer, dma_buffer, size);
    
    // 清理
    dma_unmap_sg(ctx->dev, &sg, 1, DMA_DEV_TO_MEM);
    dma_free_coherent(ctx->dev, size, dma_buffer, dma_handle);
    
    return 0;
}

// 内存读取线程
static int memory_reader_thread(void *data)
{
    struct stealth_reader *ctx = (struct stealth_reader *)data;
    
    while (!kthread_should_stop()) {
        // 等待请求
        if (!atomic_read(&ctx->ctrl->request_flag)) {
            msleep_interruptible(10);
            continue;
        }
        
        // 获取请求参数
        phys_addr_t target_addr = ctx->ctrl->target_addr;
        size_t size = ctx->ctrl->data_size;
        size_t offset = ctx->ctrl->data_offset;
        
        // 限制最大传输大小
        if (size > ctx->hw_config.max_transfer_size) {
            pr_warn("Request size %zu exceeds max transfer size %u\n",
                   size, ctx->hw_config.max_transfer_size);
            size = ctx->hw_config.max_transfer_size;
        }
        
        // 执行内存读取
        void *target_buffer = ctx->data_area + offset;
        int ret = dma_read_memory(ctx, target_addr, target_buffer, size);
        
        if (ret == 0) {
            // 计算并存储CRC校验
            ctx->ctrl->crc32 = calculate_crc32(target_buffer, size);
        }
        
        // 清除请求标志，设置就绪标志
        atomic_set(&ctx->ctrl->request_flag, 0);
        atomic_set(&ctx->ctrl->ready_flag, 1);
        
        // 通知客户端
        kill_pid(find_vpid(ctx->ctrl->client_pid), SIGNAL_NUM, 1);
    }
    
    return 0;
}

// 初始化共享内存
static int init_shared_memory(struct stealth_reader *ctx)
{
    // 分配连续物理内存
    ctx->shared_virt_addr = dma_alloc_coherent(ctx->dev, SHARED_MEM_SIZE,
                                             &ctx->shared_phys_addr, 
                                             GFP_KERNEL | __GFP_ZERO);
    if (!ctx->shared_virt_addr) {
        pr_err("Failed to allocate shared memory\n");
        return -ENOMEM;
    }
    
    // 设置控制结构
    ctx->ctrl = (struct shared_mem_control *)ctx->shared_virt_addr;
    atomic_set(&ctx->ctrl->ready_flag, 1);
    atomic_set(&ctx->ctrl->request_flag, 0);
    ctx->ctrl->client_pid = 0;
    ctx->ctrl->crc32 = 0;
    
    // 数据区域 (控制结构后)
    ctx->data_area = (void *)((char *)ctx->shared_virt_addr + 
                             sizeof(struct shared_mem_control));
    
    pr_info("Shared memory initialized at phys: 0x%llx\n",
          (u64)ctx->shared_phys_addr);
    return 0;
}

// 初始化信号处理
static int init_signal_handler(void)
{
    struct kernel_siginfo info;
    struct sigaction sa;
    
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = (void (*)(int, siginfo_t *, void *))signal_handler;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;
    sigemptyset(&sa.sa_mask);
    
    if (sigaction(SIGNAL_NUM, &sa, NULL)) {
        pr_err("Failed to register signal handler\n");
        return -EFAULT;
    }
    
    pr_info("Signal handler registered for signal %d\n", SIGNAL_NUM);
    return 0;
}

// 创建伪随机proc入口
static int create_stealth_proc_entry(struct stealth_reader *ctx)
{
    char proc_name[16];
    snprintf(proc_name, sizeof(proc_name), "driver_%lx", get_random_long());
    
    ctx->proc_entry = proc_create(proc_name, 0444, NULL, NULL);
    if (!ctx->proc_entry) {
        pr_warn("Failed to create proc entry\n");
        return -EINVAL;
    }
    
    // 在proc entry中存储物理地址信息
    char info_buf[64];
    snprintf(info_buf, sizeof(info_buf), "0x%llx:%d", 
            (u64)ctx->shared_phys_addr, SIGNAL_NUM);
    
    proc_set_size(ctx->proc_entry, strlen(info_buf) + 1);
    if (proc_write(ctx->proc_entry, info_buf, strlen(info_buf), 0) < 0) {
        pr_warn("Failed to write to proc entry\n");
    }
    
    return 0;
}

// 平台驱动探测函数
static int stealth_reader_probe(struct platform_device *pdev)
{
    int ret;
    
    pr_info("Probing Stealth Memory Reader\n");
    
    reader_ctx = devm_kzalloc(&pdev->dev, sizeof(*reader_ctx), GFP_KERNEL);
    if (!reader_ctx) 
        return -ENOMEM;
    
    reader_ctx->dev = &pdev->dev;
    atomic_set(&reader_ctx->active, 1);
    
    // 初始化Gen2+ SoC DMA
    if ((ret = init_gen2_dma(reader_ctx))) 
        return ret;
    
    // 初始化共享内存
    if ((ret = init_shared_memory(reader_ctx))) 
        goto release_dma;
    
    // 注册信号处理
    if ((ret = init_signal_handler())) 
        goto free_mem;
    
    // 创建伪随机proc入口
    if (create_stealth_proc_entry(reader_ctx))
        goto free_mem;
    
    // 启动读取线程
    reader_ctx->signal_thread = kthread_run(memory_reader_thread, 
                                          reader_ctx, "dma_reader_thread");
    if (IS_ERR(reader_ctx->signal_thread)) {
        ret = PTR_ERR(reader_ctx->signal_thread);
        goto remove_proc;
    }
    
    platform_set_drvdata(pdev, reader_ctx);
    pr_info("Stealth Memory Reader initialized\n");
    return 0;
    
remove_proc:
    if (reader_ctx->proc_entry)
        proc_remove(reader_ctx->proc_entry);
free_mem:
    if (reader_ctx->shared_virt_addr)
        dma_free_coherent(reader_ctx->dev, SHARED_MEM_SIZE, 
                         reader_ctx->shared_virt_addr, 
                         reader_ctx->shared_phys_addr);
release_dma:
    if (reader_ctx->dma_chan)
        dma_release_channel(reader_ctx->dma_chan);
    return ret;
}

static int stealth_reader_remove(struct platform_device *pdev)
{
    struct stealth_reader *ctx = platform_get_drvdata(pdev);
    
    if (!ctx) 
        return 0;
    
    pr_info("Removing Stealth Memory Reader\n");
    
    atomic_set(&ctx->active, 0);
    
    // 停止读取线程
    if (ctx->signal_thread)
        kthread_stop(ctx->signal_thread);
    
    // 移除proc入口
    if (ctx->proc_entry)
        proc_remove(ctx->proc_entry);
    
    // 释放共享内存
    if (ctx->shared_virt_addr)
        dma_free_coherent(ctx->dev, SHARED_MEM_SIZE, 
                         ctx->shared_virt_addr, 
                         ctx->shared_phys_addr);
    
    // 释放DMA通道
    if (ctx->dma_chan)
        dma_release_channel(ctx->dma_chan);
    
    return 0;
}

static const struct of_device_id stealth_reader_of_match[] = {
    { .compatible = "stealth,memory-reader" },
    { }
};
MODULE_DEVICE_TABLE(of, stealth_reader_of_match);

static struct platform_driver stealth_reader_driver = {
    .driver = {
        .name = "stealth_mem_reader",
        .of_match_table = stealth_reader_of_match,
    },
    .probe = stealth_reader_probe,
    .remove = stealth_reader_remove,
};

module_platform_driver(stealth_reader_driver);
