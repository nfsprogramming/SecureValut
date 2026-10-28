package com.securevault.ui

import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.ImageView
import android.widget.TextView
import androidx.recyclerview.widget.RecyclerView
import com.securevault.R
import com.securevault.vault.ItemSummary
import com.securevault.vault.ItemType

class ItemAdapter(private val onClick: (ItemSummary) -> Unit) : RecyclerView.Adapter<ItemAdapter.VH>() {
    private var items: List<ItemSummary> = emptyList()

    fun submit(list: List<ItemSummary>) {
        items = list
        notifyDataSetChanged()
    }

    class VH(v: View) : RecyclerView.ViewHolder(v) {
        val title: TextView = v.findViewById(R.id.titleText)
        val type: TextView = v.findViewById(R.id.typeText)
        val icon: ImageView = v.findViewById(R.id.itemIcon)
        val tile: View? = v.findViewById(R.id.itemTile)
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int) =
        VH(LayoutInflater.from(parent.context).inflate(R.layout.item_row, parent, false))

    override fun onBindViewHolder(holder: VH, position: Int) {
        val item = items[position]
        holder.title.text = item.title
        val typeName = item.type.name
        holder.type.text = "$typeName · AES-GCM"

        when (item.type) {
            ItemType.NOTE -> {
                holder.icon.setImageResource(R.drawable.ic_note)
                holder.icon.setColorFilter(holder.itemView.context.getColor(R.color.vault_emerald_primary))
                holder.tile?.setBackgroundResource(R.drawable.bg_tile_note)
            }
            ItemType.CREDENTIAL -> {
                holder.icon.setImageResource(R.drawable.ic_credential)
                holder.icon.setColorFilter(holder.itemView.context.getColor(R.color.vault_signal_amber))
                holder.tile?.setBackgroundResource(R.drawable.bg_tile_credential)
            }
            ItemType.FILE -> {
                holder.icon.setImageResource(R.drawable.ic_file)
                holder.icon.setColorFilter(holder.itemView.context.getColor(R.color.vault_signal_violet))
                holder.tile?.setBackgroundResource(R.drawable.bg_tile_file)
            }
        }
        holder.itemView.setOnClickListener { onClick(item) }
    }

    override fun getItemCount() = items.size
}
